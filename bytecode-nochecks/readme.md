# Python Exploitation Using Crafted Bytecode

This exploit uses the fact that there are no bound checks in the CPython interpreter. Take a look at this piece of code. (This is in `cpython/Python/ceval.c`)

```

#define GETITEM(v, i) PyTuple_GET_ITEM((PyTupleObject *)(v), (i))


case TARGET(LOAD_CONST): {
            PREDICTED(LOAD_CONST);
            PyObject *value = GETITEM(consts, oparg);
            Py_INCREF(value);
            PUSH(value);
            FAST_DISPATCH();
        }
```

It says that PyTuple_GET_ITEM does not check if its second argument is out of bounds. This means that if we can pass a malicious consts and oparg argument to the LOAD_CONST opcode we can fake a Python Object, which is a very powerful primitive.


## How the bytecode interpreter works

We can figure this out by looking at the source code (`ceval.c`). The important function to look at is 
`PyObject* _Py_HOT_FUNCTION _PyEval_EvalFrameDefault(PyFrameObject *f, int throwflag)`. Simply, the function is a loop that iterates through bytecode and executes runtime instructions via a classical switch-case structure common in virtual machines.


Now where exactly is the bytecode located? 

```
co = f->f_code;
names = co->co_names;
consts = co->co_consts;
fastlocals = f->f_localsplus;
freevars = f->f_localsplus + co->co_nlocals;
first_instr = (_Py_CODEUNIT *) PyBytes_AS_STRING(co->co_code);
```

Obviously, first_instr must be the pointer to the bytecode starting point. Also, `co->co_code` must be a python bytearray structure that contains bytecode. Now, `co` is a `f->f_code` structure. Let's look at the definition of `PyFrameObject` structure.

```
typedef struct _frame {
    PyObject_VAR_HEAD
    struct _frame *f_back;      /* previous frame, or NULL */
    PyCodeObject *f_code;       /* code segment */
    PyObject *f_builtins;       /* builtin symbol table (PyDictObject) */
    PyObject *f_globals;        /* global symbol table (PyDictObject) */
    PyObject *f_locals;         /* local symbol table (any mapping) */
    PyObject **f_valuestack;    /* points after the last local */
    /* Next free slot in f_valuestack.  Frame creation sets to f_valuestack.
       Frame evaluation usually NULLs it, but a frame that yields sets it
       to the current stack top. */
    PyObject **f_stacktop;
    PyObject *f_trace;          /* Trace function */
    char f_trace_lines;         /* Emit per-line trace events? */
    char f_trace_opcodes;       /* Emit per-opcode trace events? */

    /* Borrowed reference to a generator, or NULL */
    PyObject *f_gen;

    int f_lasti;                /* Last instruction if called */
    /* Call PyFrame_GetLineNumber() instead of reading this field
       directly.  As of 2.3 f_lineno is only valid when tracing is
       active (i.e. when f_trace is set).  At other times we use
       PyCode_Addr2Line to calculate the line from the current
       bytecode index. */
    int f_lineno;               /* Current line number */
    int f_iblock;               /* index in f_blockstack */
    char f_executing;           /* whether the frame is still executing */
    PyTryBlock f_blockstack[CO_MAXBLOCKS]; /* for try and loop blocks */
    PyObject *f_localsplus[1];  /* locals+stack, dynamically sized */
} PyFrameObject;
```

f_code is a pointer to a `PyCodeObject`