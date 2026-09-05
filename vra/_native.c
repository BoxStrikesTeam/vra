/*
 * vra._native - Performance-critical routines for VRA
 *
 * Provides C-accelerated implementations of:
 *   - Call graph construction (file scanning + C function parsing)
 *   - Function location (find enclosing function for a source line)
 *   - Code snippet extraction
 *   - BFS path finding on call graphs
 */

#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <structmember.h>
#include <dirent.h>
#include <sys/stat.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

/* =========================================================================
 * Utility: read entire file into malloc'd buffer
 * ========================================================================= */

static char *read_file(const char *path, size_t *out_len) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    if (len <= 0) { fclose(f); return NULL; }
    fseek(f, 0, SEEK_SET);
    char *buf = (char *)malloc((size_t)len + 1);
    if (!buf) { fclose(f); return NULL; }
    size_t rd = fread(buf, 1, (size_t)len, f);
    fclose(f);
    buf[rd] = '\0';
    *out_len = rd;
    return buf;
}

/* =========================================================================
 * Utility: recursively find .c/.cpp/.cc files under a directory
 * ========================================================================= */

static PyObject *find_source_files(PyObject *self, PyObject *args) {
    const char *root;
    if (!PyArg_ParseTuple(args, "s", &root))
        return NULL;

    PyObject *list = PyList_New(0);
    if (!list) return NULL;

    /* We'll use a stack-based DFS to avoid recursion depth issues */
    size_t stack_cap = 256;
    size_t stack_len = 0;
    char **stack = (char **)malloc(stack_cap * sizeof(char *));
    if (!stack) { Py_DECREF(list); return PyErr_NoMemory(); }

    stack[stack_len++] = strdup(root);

    DIR *dir;
    struct dirent *entry;
    char path[4096];

    while (stack_len > 0) {
        char *dirpath = stack[--stack_len];

        /* Skip hidden directories */
        const char *base = strrchr(dirpath, '/');
        if (base && *(base + 1) == '.') { free(dirpath); continue; }

        dir = opendir(dirpath);
        if (!dir) { free(dirpath); continue; }

        while ((entry = readdir(dir)) != NULL) {
            if (entry->d_name[0] == '.') continue;

            int n = snprintf(path, sizeof(path), "%s/%s", dirpath, entry->d_name);

            struct stat st;
            if (stat(path, &st) != 0) continue;

            if (S_ISDIR(st.st_mode)) {
                if (stack_len >= stack_cap) {
                    stack_cap *= 2;
                    stack = (char **)realloc(stack, stack_cap * sizeof(char *));
                }
                stack[stack_len++] = strdup(path);
            } else if (S_ISREG(st.st_mode)) {
                const char *ext = strrchr(entry->d_name, '.');
                if (ext && (strcmp(ext, ".c") == 0 ||
                            strcmp(ext, ".cpp") == 0 ||
                            strcmp(ext, ".cc") == 0 ||
                            strcmp(ext, ".h") == 0 ||
                            strcmp(ext, ".hpp") == 0)) {
                    PyObject *py_path = PyUnicode_FromString(path);
                    if (py_path) {
                        PyList_Append(list, py_path);
                        Py_DECREF(py_path);
                    }
                }
            }
        }
        closedir(dir);
        free(dirpath);
    }

    free(stack);
    return list;
}

/* =========================================================================
 * C function definition parser
 *
 * Matches: [static|extern|inline]* [return_type] [*] func_name(args) {
 * Simple heuristic - matches opening brace of function body.
 * ========================================================================= */

static int is_control_keyword(const char *s, size_t len) {
    static const char *keywords[] = {
        "if", "while", "for", "switch", "do", "return", "else", "typedef", NULL
    };
    for (int i = 0; keywords[i]; i++) {
        size_t klen = strlen(keywords[i]);
        if (len == klen && memcmp(s, keywords[i], len) == 0) return 1;
    }
    return 0;
}

typedef struct {
    const char *name;
    size_t name_len;
    size_t start;  /* byte offset of function body start (the opening brace) */
    size_t def_start; /* byte offset where function definition begins */
    size_t paren_open;  /* offset of '(' after function name */
    size_t paren_close; /* offset just after matching ')' */
} FuncDef;

static FuncDef *parse_function_defs(const char *content, size_t content_len,
                                     int *out_count) {
    int cap = 1024;
    int count = 0;
    FuncDef *defs = (FuncDef *)malloc(cap * sizeof(FuncDef));
    if (!defs) return NULL;

    size_t i = 0;
    while (i < content_len) {
        /* Skip to a line that might start a function def:
         * Look for: identifier followed by '(' at roughly column 0-ish
         * after a ; or } or newline */
        if (content[i] != '\n' && i > 0) { i++; continue; }
        i++; /* skip the newline */

        /* Skip leading whitespace */
        size_t line_start = i;
        while (i < content_len && (content[i] == ' ' || content[i] == '\t')) i++;
        if (i >= content_len) break;

        /* Skip qualifiers: static, extern, inline, __attribute__, etc. */
        while (1) {
            /* Skip type qualifiers and return types */
            size_t word_start = i;
            while (i < content_len && (isalnum(content[i]) || content[i] == '_')) i++;
            size_t word_len = i - word_start;

            if (word_len == 0) break;

            /* Check for common qualifiers */
            if (word_len == 6 && memcmp(content + word_start, "static", 6) == 0) goto skip_qual;
            if (word_len == 6 && memcmp(content + word_start, "extern", 6) == 0) goto skip_qual;
            if (word_len == 6 && memcmp(content + word_start, "inline", 6) == 0) goto skip_qual;
            if (word_len == 13 && memcmp(content + word_start, "__attribute__", 13) == 0) goto skip_qual;

            /* This might be the return type or function name */
            /* We need to find: word ( followed by ... ) followed by { */
            /* Try to find a '(' after current position */
            size_t scan = i;
            while (scan < content_len && content[scan] != '(' && content[scan] != ';' &&
                   content[scan] != '{' && content[scan] != '\n') scan++;

            if (scan < content_len && content[scan] == '(') {
                /* Found '(' - now check if what precedes it is a function name */
                /* The function name is the word right before '(' */
                size_t paren_pos = scan;
                /* Find the identifier just before '(' */
                size_t fn_end = paren_pos;
                while (fn_end > word_start && (content[fn_end - 1] == ' ' ||
                       content[fn_end - 1] == '*' || content[fn_end - 1] == '\t'))
                    fn_end--;

                /* Get the function name */
                size_t fn_start = fn_end;
                while (fn_start > word_start && (isalnum(content[fn_start - 1]) ||
                       content[fn_start - 1] == '_'))
                    fn_start--;

                size_t fn_len = fn_end - fn_start;
                if (fn_len > 0 && fn_len < 256 && !is_control_keyword(content + fn_start, fn_len)) {
                    /* Now find the matching '{' */
                    size_t j = paren_pos + 1;
                    int depth = 1;
                    while (j < content_len && depth > 0) {
                        if (content[j] == '(') depth++;
                        else if (content[j] == ')') depth--;
                        j++;
                    }
                    /* j is now right after the closing ')' */
                    /* Skip whitespace/newlines to find '{' */
                    while (j < content_len && (content[j] == ' ' || content[j] == '\t' ||
                           content[j] == '\n' || content[j] == '\r')) j++;

                    if (j < content_len && content[j] == '{') {
                        if (count >= cap) {
                            cap *= 2;
                            defs = (FuncDef *)realloc(defs, cap * sizeof(FuncDef));
                        }
                        defs[count].name = content + fn_start;
                        defs[count].name_len = fn_len;
                        defs[count].start = j;
                        defs[count].def_start = line_start;
                        defs[count].paren_open = paren_pos;
                        defs[count].paren_close = j;
                        count++;
                    }
                }
            }
            break; /* Only process first non-qualifier word */

            skip_qual:
            /* Skip past any remaining chars to find next word */
            while (i < content_len && content[i] != ' ' && content[i] != '\t' &&
                   content[i] != '\n') i++;
            i++; /* skip space */
        }
    }

    *out_count = count;
    return defs;
}

/* =========================================================================
 * File-level function range cache
 *
 * Each source file is parsed ONCE into a normalized list of
 * (start_line, end_line, start_offset, end_offset, name) entries. Subsequent
 * lookups for the same file are O(log n) binary searches instead of a full
 * re-parse. This is the critical optimization for very large vendored files
 * (e.g. sqlite3.c) that many findings point into.
 * ========================================================================= */

typedef struct {
    int start_line;
    int end_line;
    char *name;
} CachedFunc;

typedef struct {
    char *path;
    unsigned char *deleted;   /* not used; kept for structural clarity */
    CachedFunc *funcs;
    int func_count;
    long last_use;
} FuncFileCache;

#define CACHE_CAPACITY 512

static FuncFileCache g_cache[CACHE_CAPACITY];
static int g_cache_len = 0;
static int g_cache_gen = 0;   /* increments on every cache access, enables LRU */

/* Bump access recency for a cache index (LRU). */
static void cache_touch(int idx) {
    g_cache[idx].last_use = ++g_cache_gen;
}

/* Find the least-recently-used cache slot for eviction. */
static int cache_lru_victim(void) {
    int victim = 0;
    long oldest = g_cache[0].last_use;
    for (int i = 1; i < g_cache_len; i++) {
        if (g_cache[i].path && g_cache[i].last_use < oldest) {
            oldest = g_cache[i].last_use;
            victim = i;
        }
    }
    return victim;
}

static void cache_func_entries_free(FuncFileCache *fc) {
    for (int i = 0; i < fc->func_count; i++) {
        if (fc->funcs[i].name) free(fc->funcs[i].name);
    }
    free(fc->funcs);
    fc->funcs = NULL;
    fc->func_count = 0;
}

static void clear_func_cache(void) {
    for (int i = 0; i < g_cache_len; i++) {
        if (g_cache[i].path) free(g_cache[i].path);
        cache_func_entries_free(&g_cache[i]);
        g_cache[i].path = NULL;
    }
    g_cache_len = 0;
    g_cache_gen = 0;
}

/* Look up a file in the cache. Returns index or -1. */
static int cache_find(const char *path) {
    for (int i = 0; i < g_cache_len; i++) {
        if (g_cache[i].path && strcmp(g_cache[i].path, path) == 0) {
            cache_touch(i);
            return i;
        }
    }
    return -1;
}

/* Parse a file into cached function ranges. Returns cache index or -1 on error. */
static int cache_parse_file(const char *path) {
    size_t content_len;
    char *content = read_file(path, &content_len);
    if (!content) return -1;

    int nlines = 1;
    for (size_t i = 0; i < content_len; i++)
        if (content[i] == '\n') nlines++;

    /* line_of[byte_index] = line number (0-based byte line). Build in O(n). */
    int *line_at = (int *)malloc((content_len + 1) * sizeof(int));
    int cur = 1;
    for (size_t i = 0; i <= content_len; i++) {
        line_at[i] = cur;
        if (i < content_len && content[i] == '\n') cur++;
    }

    int def_count = 0;
    FuncDef *defs = parse_function_defs(content, content_len, &def_count);
    if (!defs) {
        free(line_at);
        free(content);
        if (g_cache_len < CACHE_CAPACITY) {
            FuncFileCache *fc = &g_cache[g_cache_len];
            fc->path = strdup(path);
            fc->funcs = NULL;
            fc->func_count = 0;
            fc->last_use = ++g_cache_gen;
            return g_cache_len++;
        }
        return -1;
    }

    /* If cache full, evict the least-recently-used entry (LRU) */
    int idx;
    if (g_cache_len < CACHE_CAPACITY) {
        idx = g_cache_len++;
    } else {
        idx = cache_lru_victim();
        if (g_cache[idx].path) free(g_cache[idx].path);
        cache_func_entries_free(&g_cache[idx]);
        g_cache[idx].path = NULL;
    }

    FuncFileCache *fc = &g_cache[idx];
    fc->path = strdup(path);
    fc->funcs = (CachedFunc *)calloc(def_count > 0 ? def_count : 1, sizeof(CachedFunc));
    fc->func_count = 0;
    fc->last_use = ++g_cache_gen;

    /* Build line-indexed entries: compute start/end line via O(1) line_at lookups */
    for (int d = 0; d < def_count; d++) {
        int start_line = line_at[defs[d].start];
        /* Find matching close brace to compute end line */
        size_t end = defs[d].start + 1;
        int depth = 1;
        while (end < content_len && depth > 0) {
            if (content[end] == '{') depth++;
            else if (content[end] == '}') depth--;
            end++;
        }
        int end_line = end <= content_len ? line_at[end - 1] : start_line;

        fc->funcs[fc->func_count].start_line = start_line;
        fc->funcs[fc->func_count].end_line = end_line;
        fc->funcs[fc->func_count].name = strndup(defs[d].name, defs[d].name_len);
        fc->func_count++;
    }

    free(line_at);
    free(defs);
    free(content);
    g_cache_gen++;
    return idx;
}

/* Get cached index for a file (parse if needed). Returns -1 on failure. */
static int cache_lookup(const char *path) {
    int idx = cache_find(path);
    if (idx != -1) return idx;
    return cache_parse_file(path);
}

/* Find name of enclosing function for a line via cached binary search. */
static const char *cached_find_function(const char *path, int line, size_t *name_len) {
    int idx = cache_lookup(path);
    *name_len = 0;
    if (idx < 0) return "";

    FuncFileCache *fc = &g_cache[idx];
    int lo = 0, hi = fc->func_count - 1, best = -1;
    while (lo <= hi) {
        int mid = (lo + hi) / 2;
        if (fc->funcs[mid].start_line <= line) {
            best = mid;
            lo = mid + 1;
        } else {
            hi = mid - 1;
        }
    }
    if (best >= 0 && line <= fc->funcs[best].end_line) {
        *name_len = strlen(fc->funcs[best].name);
        return fc->funcs[best].name;
    }
    return "";
}

/* =========================================================================
 * build_call_graph(source_dir) -> dict
 *
 * Returns: {
 *   "functions": {name: [callee, ...], ...},
 *   "function_files": {name: relative_path, ...},
 *   "entry_points": [name, ...]
 * }
 * ========================================================================= */

static PyObject *py_build_call_graph(PyObject *self, PyObject *args) {
    const char *source_dir;
    if (!PyArg_ParseTuple(args, "s", &source_dir))
        return NULL;

    PyObject *py_files = find_source_files(self, args);
    if (!py_files) return NULL;

    Py_ssize_t num_files = PyList_Size(py_files);

    PyObject *functions = PyDict_New();
    PyObject *function_files = PyDict_New();
    PyObject *entry_points = PyList_New(0);
    PyObject *all_defs = PyDict_New(); /* name -> (file_rel, start_offset) */

    if (!functions || !function_files || !entry_points || !all_defs) {
        Py_XDECREF(functions); Py_XDECREF(function_files);
        Py_XDECREF(entry_points); Py_XDECREF(all_defs);
        Py_DECREF(py_files);
        return NULL;
    }

    size_t root_len = strlen(source_dir);

    for (Py_ssize_t fi = 0; fi < num_files; fi++) {
        PyObject *py_path = PyList_GetItem(py_files, fi);
        const char *filepath = PyUnicode_AsUTF8(py_path);
        if (!filepath) continue;

        /* Get relative path */
        const char *rel = filepath + root_len;
        if (*rel == '/') rel++;

        size_t content_len;
        char *content = read_file(filepath, &content_len);
        if (!content) continue;

        /* Parse function definitions */
        int def_count = 0;
        FuncDef *defs = parse_function_defs(content, content_len, &def_count);

        if (!defs) { free(content); continue; }

        /* For each function definition, extract calls */
        for (int di = 0; di < def_count; di++) {
            PyObject *py_name = PyUnicode_FromStringAndSize(defs[di].name, defs[di].name_len);
            if (!py_name) continue;

            /* Add to function_files */
            PyObject *py_rel = PyUnicode_FromString(rel);
            PyDict_SetItem(function_files, py_name, py_rel);
            Py_DECREF(py_rel);

            /* Add empty callee list */
            PyObject *empty_list = PyList_New(0);
            PyDict_SetItem(functions, py_name, empty_list);
            Py_DECREF(empty_list);

            /* Check if it's an entry point */
            if (defs[di].name_len == 4 && memcmp(defs[di].name, "main", 4) == 0) {
                PyList_Append(entry_points, py_name);
            } else {
                /* Check for entry-point-like names */
                char lower[256];
                size_t nlen = defs[di].name_len < 255 ? defs[di].name_len : 255;
                memcpy(lower, defs[di].name, nlen);
                lower[nlen] = '\0';
                for (size_t k = 0; k < nlen; k++) lower[k] = tolower(lower[k]);

                const char *hints[] = {"exit", "hook", "dispatch", "poll", "loop",
                                       "event", "handle", "init", NULL};
                for (int h = 0; hints[h]; h++) {
                    if (strstr(lower, hints[h])) {
                        PyList_Append(entry_points, py_name);
                        break;
                    }
                }
            }

            /* Extract function body and find calls */
            /* Body starts at defs[di].start, ends at matching '}' */
            size_t body_start = defs[di].start + 1; /* skip opening '{' */
            int depth = 1;
            size_t body_end = body_start;
            while (body_end < content_len && depth > 0) {
                if (content[body_end] == '{') depth++;
                else if (content[body_end] == '}') depth--;
                body_end++;
            }
            if (depth != 0) body_end = content_len;

            /* Parse calls from body using simple word( detection */
            PyObject *callees = PyList_New(0);
            size_t bi = body_start;
            while (bi < body_end) {
                /* Find next word followed by '(' */
                while (bi < body_end && !isalnum(content[bi]) && content[bi] != '_') bi++;
                if (bi >= body_end) break;

                size_t word_start = bi;
                while (bi < body_end && (isalnum(content[bi]) || content[bi] == '_')) bi++;
                size_t word_len = bi - word_start;

                /* Skip whitespace to check for '(' */
                size_t si = bi;
                while (si < body_end && (content[si] == ' ' || content[si] == '\t' ||
                       content[si] == '\n' || content[si] == '\r')) si++;

                if (si < body_end && content[si] == '(' && word_len > 0 && word_len < 256) {
                    /* This is a call - check if callee is a known function */
                    PyObject *py_callee = PyUnicode_FromStringAndSize(content + word_start, word_len);
                    if (py_callee) {
                        /* Check if callee is in functions dict (i.e., is a defined function) */
                        if (PyDict_GetItem(functions, py_callee) != NULL) {
                            /* Don't add self-calls */
                            PyObject *is_self = PyLong_FromLong(
                                word_len == defs[di].name_len &&
                                memcmp(content + word_start, defs[di].name, word_len) == 0);
                            if (!PyLong_AsLong(is_self)) {
                                /* Check for duplicates */
                                int found = 0;
                                for (Py_ssize_t ci = 0; ci < PyList_Size(callees); ci++) {
                                    PyObject *existing = PyList_GetItem(callees, ci);
                                    if (PyUnicode_Compare(existing, py_callee) == 0) {
                                        found = 1;
                                        break;
                                    }
                                }
                                if (!found) PyList_Append(callees, py_callee);
                            }
                            Py_DECREF(is_self);
                        }
                        Py_DECREF(py_callee);
                    }
                    bi = si + 1; /* skip past '(' */
                }
            }

            /* Set callees in functions dict */
            PyDict_SetItem(functions, py_name, callees);
            Py_DECREF(callees);
            Py_DECREF(py_name);
        }

        free(defs);
        free(content);
    }

    /* Build result dict */
    PyObject *result = PyDict_New();
    PyDict_SetItemString(result, "functions", functions);
    PyDict_SetItemString(result, "function_files", function_files);
    PyDict_SetItemString(result, "entry_points", entry_points);

    Py_DECREF(functions);
    Py_DECREF(function_files);
    Py_DECREF(entry_points);
    Py_DECREF(all_defs);
    Py_DECREF(py_files);

    return result;
}

/* =========================================================================
 * build_taint_data(source_dir) -> dict
 *
 * Enriches the call graph with data-flow primitives needed for taint
 * analysis:
 *   {
 *     "params":  {func_name: [param_name, ...], ...},
 *     "calls":   {func_name: [{"callee": n, "args": [arg,...], "line": L}, ...]},
 *     "assigns": {func_name: [{"var": v, "value": expr, "line": L}, ...]},
 *   }
 *
 * Values that are not simple identifiers (e.g. "a[i]", "sizeof(x)") are still
 * recorded as raw substrings; taint resolution happens in the Python engine.
 * ========================================================================= */

/* Copy a token region into a freshly malloc'd, NUL-terminated string. */
static char *strndup_safe(const char *s, size_t n) {
    char *out = (char *)malloc(n + 1);
    if (!out) return NULL;
    memcpy(out, s, n);
    out[n] = '\0';
    return out;
}

/* Extract parameter/argument names from the region between two parens.
 * `open` is the offset just after '(' (i.e. first char of body).
 * `close` is the offset just before ')' (last char of body + 1) exclusive.
 * Returns a PyList of trimmed token strings (last word of each comma part).
 * want_last_word=1 => return just the final identifier (for params);
 * =0 => return the raw trimmed substring (for call args). */
static PyObject *extract_paren_items(const char *content, size_t open, size_t close,
                                     int want_last_word) {
    PyObject *list = PyList_New(0);
    if (!list) return NULL;

    /* Skip a stray leading '(' if present */
    if (open < close && content[open] == '(') open++;

    size_t i = open;
    size_t last = open;
    while (i < close) {
        if (content[i] == ',') {
            size_t e = i - 1;
            while (e > last && (content[e]==')'||content[e]==' '||content[e]=='\t'||content[e]=='\r'||content[e]=='\n')) e--;
            char *tok = strndup_safe(content + last, e - last + 1);
            if (tok) {
                size_t tlen = strlen(tok);
                while (tlen > 0 && (isspace((unsigned char)tok[tlen-1]))) tok[--tlen] = '\0';
                while (tlen > 0 && tok[tlen-1]==')' ) tok[--tlen] = '\0';
                size_t s = 0;
                while (s < tlen && isspace((unsigned char)tok[s])) s++;
                while (s < tlen && tok[s]=='(') s++;
                const char *p = tok + s;
                size_t plen = tlen - s;
                if (want_last_word) {
                    size_t w = plen;
                    while (w > 0 && (isalnum((unsigned char)p[w-1]) || p[w-1]=='_')) w--;
                    if (w < plen) p = p + w, plen = plen - w;
                    else p = "", plen = 0;
                }
                if (plen > 0) {
                    PyObject *py = PyUnicode_FromStringAndSize(p, plen);
                    if (py) { PyList_Append(list, py); Py_DECREF(py); }
                }
                free(tok);
            }
            last = i + 1;
        }
        i++;
    }
    /* Last item after final comma */
    if (last < close) {
        size_t e = close - 1;
        while (e > last && (content[e]==')'||content[e]==' '||content[e]=='\t'||content[e]=='\r'||content[e]=='\n')) e--;
        char *tok = strndup_safe(content + last, e - last + 1);
        if (tok) {
            size_t tlen = strlen(tok);
            while (tlen > 0 && (isspace((unsigned char)tok[tlen-1]))) tok[--tlen] = '\0';
            while (tlen > 0 && tok[tlen-1]==')' ) tok[--tlen] = '\0';
            size_t s = 0;
            while (s < tlen && isspace((unsigned char)tok[s])) s++;
            while (s < tlen && tok[s]=='(') s++;
            const char *p = tok + s;
            size_t plen = tlen - s;
            if (want_last_word) {
                size_t w = plen;
                while (w > 0 && (isalnum((unsigned char)p[w-1]) || p[w-1]=='_')) w--;
                if (w < plen) p = p + w, plen = plen - w;
                else p = "", plen = 0;
            }
            if (plen > 0) {
                PyObject *py = PyUnicode_FromStringAndSize(p, plen);
                if (py) { PyList_Append(list, py); Py_DECREF(py); }
            }
            free(tok);
        }
    }
    return list;
}

static PyObject *py_build_taint_data(PyObject *self, PyObject *args) {
    const char *source_dir;
    if (!PyArg_ParseTuple(args, "s", &source_dir))
        return NULL;

    PyObject *py_files = find_source_files(self, args);
    if (!py_files) return NULL;

    Py_ssize_t num_files = PyList_Size(py_files);
    PyObject *params = PyDict_New();
    PyObject *calls = PyDict_New();
    PyObject *assigns = PyDict_New();

    size_t root_len = strlen(source_dir);

    for (Py_ssize_t fi = 0; fi < num_files; fi++) {
        PyObject *py_path = PyList_GetItem(py_files, fi);
        const char *filepath = PyUnicode_AsUTF8(py_path);
        if (!filepath) continue;

        size_t content_len;
        char *content = read_file(filepath, &content_len);
        if (!content) continue;

        int def_count = 0;
        FuncDef *defs = parse_function_defs(content, content_len, &def_count);
        if (!defs) { free(content); continue; }

        /* Precompute line numbers for every byte offset (O(n)). */
        int *line_at = (int *)malloc((content_len + 1) * sizeof(int));
        int cur = 1;
        for (size_t k = 0; k <= content_len; k++) {
            line_at[k] = cur;
            if (k < content_len && content[k] == '\n') cur++;
        }

        for (int di = 0; di < def_count; di++) {
            PyObject *py_name = PyUnicode_FromStringAndSize(defs[di].name, defs[di].name_len);
            if (!py_name) continue;

            /* Params */
            PyObject *plist = extract_paren_items(content, defs[di].paren_open + 1,
                                                  defs[di].paren_close > 0 ? defs[di].paren_close - 1 : defs[di].paren_close, 1);
            PyDict_SetItem(params, py_name, plist);
            Py_DECREF(plist);

            PyObject *call_list = PyList_New(0);
            PyObject *assign_list = PyList_New(0);

            /* Scan function body for calls and assignments */
            size_t body_start = defs[di].start + 1; /* skip '{' */
            size_t body_end = content_len;
            int depth = 1;
            size_t e = body_start;
            while (e < content_len && depth > 0) {
                if (content[e] == '{') depth++;
                else if (content[e] == '}') depth--;
                e++;
            }
            if (depth == 0) body_end = e;

            size_t bi = body_start;
            while (bi < body_end) {
                /* Find next identifier start then optional '(' */
                while (bi < body_end && !isalnum(content[bi]) && content[bi] != '_') bi++;
                if (bi >= body_end) break;
                size_t ws = bi;
                while (bi < body_end && (isalnum(content[bi]) || content[bi] == '_')) bi++;
                size_t wlen = bi - ws;
                /* Skip spaces/newlines before ( or = */
                size_t si = bi;
                while (si < body_end && (content[si]==' '||content[si]=='\t'||content[si]=='\n'||content[si]=='\r')) si++;

                if (si < body_end && content[si] == '(') {
                    /* A call. Find matching closing paren (nested). */
                    size_t ci = si + 1;
                    int pd = 1;
                    while (ci < body_end && pd > 0) {
                        if (content[ci] == '(') pd++;
                        else if (content[ci] == ')') pd--;
                        ci++;
                    }
                    size_t close_paren = ci > 0 ? ci - 1 : ci;
                    PyObject *arglist = extract_paren_items(content, si, close_paren, 0);
                    PyObject *callee = PyUnicode_FromStringAndSize(content + ws, wlen);
                    int this_line = line_at[ws];
                    PyObject *entry = Py_BuildValue("(OOi)", callee, arglist, this_line);
                    PyList_Append(call_list, entry);
                    Py_DECREF(entry);
                    Py_DECREF(callee);
                    Py_DECREF(arglist);
                    bi = ci;
                    continue;
                }

                if (si < body_end && content[si] == '=' &&
                    (si + 1 >= body_end || content[si+1] != '=')) {
                    /* Assignment: read value until ';' or next statement start. */
                    /* var = value ; (skip '=' possibly nested in comparisons loosely) */
                    size_t vi = si + 1;
                    while (vi < body_end && content[vi] == ' ' || vi == si+1 && content[vi]=='=' ) vi++;
                    if (vi < body_end && content[vi] == '=') vi++; /* handle ==*/
                    size_t vs = vi;
                    while (vi < body_end && content[vi] != ';' && content[vi] != '\n') vi++;
                    size_t val_len = vi - vs;
                    PyObject *var = PyUnicode_FromStringAndSize(content + ws, wlen);
                    PyObject *value;
                    if (val_len > 0) {
                        size_t t = vs;
                        while (t < vi && isspace((unsigned char)content[t])) t++;
                        size_t t2 = vi;
                        while (t2 > t && isspace((unsigned char)content[t2-1])) t2--;
                        value = PyUnicode_FromStringAndSize(content + t, t2 - t);
                    } else {
                        value = PyUnicode_FromString("");
                    }
                    int this_line = line_at[ws];
                    PyObject *entry = Py_BuildValue("(OOi)", var, value, this_line);
                    PyList_Append(assign_list, entry);
                    Py_DECREF(entry);
                    Py_DECREF(var);
                    Py_DECREF(value);
                    bi = vi;
                    continue;
                }
                bi = si;
            }

            PyDict_SetItem(calls, py_name, call_list);
            Py_DECREF(call_list);
            PyDict_SetItem(assigns, py_name, assign_list);
            Py_DECREF(assign_list);
            Py_DECREF(py_name);
        }
        free(line_at);
        free(defs);
        free(content);
    }

    PyObject *result = PyDict_New();
    PyDict_SetItemString(result, "params", params);
    PyDict_SetItemString(result, "calls", calls);
    PyDict_SetItemString(result, "assigns", assigns);
    Py_DECREF(params);
    Py_DECREF(calls);
    Py_DECREF(assigns);
    Py_DECREF(py_files);
    return result;
}

static PyObject *py_bfs_path(PyObject *self, PyObject *args) {
    PyObject *functions;
    const char *source;
    const char *sink;
    if (!PyArg_ParseTuple(args, "Oss", &functions, &source, &sink))
        return NULL;

    /* BFS using Python dicts as visited/prev maps */
    PyObject *visited = PyDict_New();
    PyObject *prev = PyDict_New();

    PyObject *py_source = PyUnicode_FromString(source);
    PyObject *py_sink = PyUnicode_FromString(sink);

    PyDict_SetItem(visited, py_source, Py_True);
    PyDict_SetItem(prev, py_source, Py_None);

    /* Simple BFS queue using list of (node, prev_node) pairs */
    PyObject *queue = PyList_New(0);
    PyObject *first = Py_BuildValue("(OO)", py_source, Py_None);
    PyList_Append(queue, first);
    Py_DECREF(first);

    int found = 0;

    while (PyList_Size(queue) > 0) {
        PyObject *item = PyList_GetItem(queue, 0);
        PyObject *current = PyTuple_GetItem(item, 0);
        PyObject *parent = PyTuple_GetItem(item, 1);

        /* Remove first item (queue.popleft equivalent - we use index shift) */
        /* For performance, just use a new list */
        PyObject *new_queue = PyList_New(0);
        for (Py_ssize_t qi = 1; qi < PyList_Size(queue); qi++) {
            PyList_Append(new_queue, PyList_GetItem(queue, qi));
        }
        Py_DECREF(queue);
        queue = new_queue;

        /* Check if we reached sink */
        if (PyUnicode_Compare(current, py_sink) == 0) {
            /* Reconstruct path */
            PyObject *path = PyList_New(0);
            PyObject *node = py_sink;
            while (node != Py_None && node != NULL) {
                PyList_Insert(path, 0, node);
                PyObject *p = PyDict_GetItem(prev, node);
                if (p == Py_None) break;
                node = p;
            }
            Py_DECREF(visited);
            Py_DECREF(prev);
            Py_DECREF(queue);
            Py_DECREF(py_source);
            Py_DECREF(py_sink);
            return path;
        }

        /* Get callees */
        PyObject *callees = PyDict_GetItem(functions, current);
        if (callees && PyList_Check(callees)) {
            Py_ssize_t num_callees = PyList_Size(callees);
            for (Py_ssize_t ci = 0; ci < num_callees; ci++) {
                PyObject *callee = PyList_GetItem(callees, ci);
                if (!PyDict_GetItem(visited, callee)) {
                    PyDict_SetItem(visited, callee, Py_True);
                    PyDict_SetItem(prev, callee, current);
                    PyObject *new_item = Py_BuildValue("(OO)", callee, current);
                    PyList_Append(queue, new_item);
                    Py_DECREF(new_item);
                }
            }
        }
    }

    Py_DECREF(visited);
    Py_DECREF(prev);
    Py_DECREF(queue);
    Py_DECREF(py_source);
    Py_DECREF(py_sink);
    Py_RETURN_NONE;
}

/* =========================================================================
 * find_function_at(file_path, line_number) -> function_name or ""
 * ========================================================================= */

static PyObject *py_find_function_at(PyObject *self, PyObject *args) {
    const char *file_path;
    Py_ssize_t target_line;
    if (!PyArg_ParseTuple(args, "sn", &file_path, &target_line))
        return NULL;

    size_t name_len = 0;
    const char *result = cached_find_function(file_path, (int)target_line, &name_len);
    return PyUnicode_FromStringAndSize(result, name_len);
}

/* =========================================================================
 * extract_snippet(file_path, line_number, context_lines=3) -> string
 * ========================================================================= */

static PyObject *py_extract_snippet(PyObject *self, PyObject *args) {
    const char *file_path;
    Py_ssize_t target_line;
    Py_ssize_t context = 3;
    if (!PyArg_ParseTuple(args, "sn|n", &file_path, &target_line, &context))
        return NULL;

    FILE *f = fopen(file_path, "r");
    if (!f) return PyUnicode_FromString("");

    Py_ssize_t start_line = target_line - context;
    if (start_line < 1) start_line = 1;
    Py_ssize_t end_line = target_line + context;

    PyObject *result = PyUnicode_FromString("");
    char line_buf[2048];
    Py_ssize_t line_num = 0;

    while (fgets(line_buf, sizeof(line_buf), f)) {
        line_num++;
        if (line_num >= start_line && line_num <= end_line) {
            /* Strip trailing newline */
            size_t len = strlen(line_buf);
            while (len > 0 && (line_buf[len - 1] == '\n' || line_buf[len - 1] == '\r'))
                line_buf[--len] = '\0';

            PyObject *marker = (line_num == target_line) ? PyUnicode_FromString(">>>") : PyUnicode_FromString("   ");
            PyObject *py_line = PyUnicode_FromFormat("%U %zd | %s", marker, line_num, line_buf);

            PyObject *new_result = PyUnicode_FromFormat("%U\n%U", result, py_line);
            Py_DECREF(result);
            result = new_result;
            Py_DECREF(marker);
            Py_DECREF(py_line);
        }
        if (line_num > end_line) break;
    }

    fclose(f);
    return result;
}

/* =========================================================================
 * clear_caches()
 * ========================================================================= */

static PyObject *py_clear_func_cache(PyObject *self, PyObject *noargs) {
    clear_func_cache();
    Py_RETURN_NONE;
}

/* =========================================================================
 * Module definition
 * ========================================================================= */

static PyMethodDef NativeMethods[] = {
    {"build_call_graph", py_build_call_graph, METH_VARARGS,
     "Build call graph from source directory. Returns dict with functions, function_files, entry_points."},
    {"build_taint_data", py_build_taint_data, METH_VARARGS,
     "Build data-flow primitives (params, calls with args, assignments) for taint analysis."},
    {"bfs_path", py_bfs_path, METH_VARARGS,
     "Find shortest call chain from source to sink via BFS. Returns list or None."},
    {"find_function_at", py_find_function_at, METH_VARARGS,
     "Find enclosing function for a given source line. Returns function name string."},
    {"extract_snippet", py_extract_snippet, METH_VARARGS,
     "Extract code snippet around a line. Returns formatted string."},
    {"clear_caches", (PyCFunction)(void(*)(void))py_clear_func_cache, METH_NOARGS,
     "Clear the internal file-level function range cache."},
    {NULL, NULL, 0, NULL}
};

static struct PyModuleDef native_module = {
    PyModuleDef_HEAD_INIT,
    "vra._native",
    "C-accelerated routines for VRA performance-critical operations",
    -1,
    NativeMethods
};

PyMODINIT_FUNC PyInit__native(void) {
    return PyModule_Create(&native_module);
}
