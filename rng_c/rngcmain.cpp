/* Replace "dll.h" with the name of your header */
#include "dll.h"
#include <windows.h>
#include <Python.h>
#include "rngc.hpp"
#define import_py_mod(func,rfunc) func = (decltype(func)) GetProcAddress(pPyModule, #rfunc);assert(func)
class PyDllLoader {
	HMODULE pPyModule;
public:
	PyObject* (*PyModuleCreate)(PyModuleDef*, int);
	PyObject* (*PyBuildValue)(const char*, ...);
	int (*PyArgParseTuple)(PyObject*, const char*, ...);
	int (*PyBytesAsStringAndSize)(PyObject*, char**, Py_ssize_t*);
	PyObject* (*PyBytesFromStringAndSize)(char*,Py_ssize_t);
	int (*PyTypeReady)(PyTypeObject* type);
	int (*PyModuleAddObject)(PyObject*, const char*, PyObject*);
	void (*PyDealloc)(PyObject*);
	PyDllLoader() {
		pPyModule = LoadLibrary("python311.dll");
		import_py_mod(PyModuleCreate,PyModule_Create2);
		import_py_mod(PyBuildValue,Py_BuildValue);
		import_py_mod(PyArgParseTuple,PyArg_ParseTuple);
		import_py_mod(PyBytesAsStringAndSize,PyBytes_AsStringAndSize);
		import_py_mod(PyBytesFromStringAndSize,PyBytes_FromStringAndSize);
		import_py_mod(PyTypeReady,PyType_Ready);
		import_py_mod(PyModuleAddObject,PyModule_AddObject);
		import_py_mod(PyDealloc,_Py_Dealloc);
	}
} gldr;
void _Py_Dealloc(PyObject* o) {
	gldr.PyDealloc(o);
}
PyObject* py_encrypt(PyObject* self, PyObject* args) {
	PyObject* data,*key;
	if(!gldr.PyArgParseTuple(args,"SS",&data,&key)) {
		return NULL;
	}
	char* datap,*keyp;
	Py_ssize_t datas,keys;
	gldr.PyBytesAsStringAndSize(data,&datap,&datas);
	gldr.PyBytesAsStringAndSize(key,&keyp,&keys);
	if(keys != 16) {
		char err[100];
		int s = sprintf(err,"Error: expected key size=16, got %d",keys);
		return gldr.PyBytesFromStringAndSize(err,s);
	}
	vector<char> datan(datas);
	memcpy(&datan[0],datap,datas);
	encrypt(&datan[0],keyp,datas);
	return gldr.PyBytesFromStringAndSize(&datan[0],datas);
}
typedef struct {
	PyObject_HEAD
	drng* dr;
	mt19937_64* mt;
} PyRandEx;
PyObject* rand_new(PyTypeObject* type, PyObject* args, PyObject* kwds) {
	PyRandEx* self = (PyRandEx*) type->tp_alloc(type,0);
	self->dr=nullptr;
	self->mt=nullptr;
	return (PyObject*) self;
}
int rand_init(PyRandEx* self, PyObject* args, PyObject* kwargs) {
	unsigned long long seed;
	if(!gldr.PyArgParseTuple(args,"K",&seed)) {
		return -1;
	}
	self->dr=new drng(seed);
	self->mt=new mt19937_64(seed);
	return 0;
}
void rand_dealloc(PyRandEx* self) {
	delete self->dr;
	delete self->mt;
	Py_TYPE(self)->tp_free((PyObject*) self);
}
PyObject* rand_next_dr(PyRandEx* self, PyObject* args, PyObject* kwargs) {
	return gldr.PyBuildValue("K",(*self->dr)());
}
PyObject* rand_next_mt(PyRandEx* self, PyObject* args, PyObject* kwargs) {
	return gldr.PyBuildValue("K",(*self->mt)());
}
PyMethodDef rand_methods[] = {
	{"next_dr",(PyCFunction)rand_next_dr,METH_VARARGS, "rand()->unsigned long long"},
	{"next_mt",(PyCFunction)rand_next_mt,METH_VARARGS, "rand()->unsigned long long"},
	{NULL,NULL,0,NULL}
};
static PyTypeObject rand_type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	"rng.RandomGen",          // tp_name
	sizeof(PyRandEx),    // tp_basicsize
	0,                          // tp_itemsize
	(destructor)rand_dealloc, // tp_dealloc
	0,                          // tp_print
	0,                          // tp_getattr
	0,                          // tp_setattr
	0,                          // tp_as_async
	0,                          // tp_repr
	0,                          // tp_as_number
	0,                          // tp_as_sequence
	0,                          // tp_as_mapping
	0,                          // tp_hash
	0,                          // tp_call
	0,                          // tp_str
	0,                          // tp_getattro
	0,                          // tp_setattro
	0,                          // tp_as_buffer
	Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE, // tp_flags
	"Random generator",          // tp_doc
	0,                          // tp_traverse
	0,                          // tp_clear
	0,                          // tp_richcompare
	0,                          // tp_weaklistoffset
	0,                          // tp_iter
	0,                          // tp_iternext
	rand_methods,          // tp_methods
	0,                          // tp_members
	0,                          // tp_getset
	0,                          // tp_base
	0,                          // tp_dict
	0,                          // tp_descr_get
	0,                          // tp_descr_set
	0,                          // tp_dictoffset
	(initproc)rand_init,   // tp_init
	0,                          // tp_alloc
	rand_new,              // tp_new
};
PyMethodDef methods[] = {
	{"encrypt", py_encrypt,METH_VARARGS, "encrypt(data,key[16])->encrypted"},
	{NULL,NULL,0,NULL}
};
PyModuleDef modu = {
	PyModuleDef_HEAD_INIT,
	"rng",
	NULL,
	-1,
	methods
};
extern "C"
__declspec(dllexport)
PyObject* PyInit_rng() {
	if(gldr.PyTypeReady(&rand_type)<0) {
		return NULL;
	}
	PyObject* mod = gldr.PyModuleCreate(&modu, PYTHON_API_VERSION);
	if(!mod) {
		return mod;
	}
	Py_INCREF(&rand_type);
	if(gldr.PyModuleAddObject(mod,"RandomGen", (PyObject*)&rand_type)<0) {
		Py_DECREF(&rand_type);
		Py_DECREF(mod);
		return NULL;
	}
	return mod;
}
struct shmem_data {
	bool exists;
	char name[64];
	void* mem;
	shmem_data* next;
};
#define SHMEM_LENGTH 10000
shmem_data shmems[SHMEM_LENGTH];
bool first;
extern "C" void* __shmem_winpthreads_grab(char* s,int l,
        void (__fastcall *init)(void *)) {
	/*if(!strcmp("global_lock_spinlock",s)){
		return malloc(4);
	}*/
	char debugging[200];
	//sprintf(debugging,"s=%s,l=%d,init=%p",s,l,init);
	//MessageBoxA(NULL,debugging,"debug",MB_OK);
	/*if(!first) {
		first=true;
		HMODULE hModule = NULL;
		GetModuleHandleEx(
		    GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
		    (LPCTSTR)__shmem_winpthreads_grab,
		    &hModule);
		lgui_init(hModule);
	}*/
	unsigned long long hash=strlen(s);
	for(char* i=s; *i; i++) {
		hash ^= *i;
		hash *= 998244353;
	}
	hash %= SHMEM_LENGTH;
	if(shmems[hash].exists) {
		for(shmem_data* m=shmems+hash; m; m=m->next) {
			if(!strcmp(m->name,s)) {
				return m->mem;
			}
		}
		shmem_data d1;
		d1.exists=true;
		strcpy(d1.name,s);
		d1.mem=malloc(l);
		memset(d1.mem,0,l);
		if(init) init(d1.mem);
		d1.next=(shmem_data*)malloc(sizeof(shmem_data));
		memcpy(d1.next,shmems+hash,sizeof(shmem_data));
		memcpy(shmems+hash,&d1,sizeof(shmem_data));
		return d1.mem;
	} else {
		shmems[hash].exists=true;
		strcpy(shmems[hash].name,s);
		shmems[hash].mem=malloc(l);
		memset(shmems[hash].mem,0,l);
		if(init) init(shmems[hash].mem);
		shmems[hash].next=nullptr;
		return shmems[hash].mem;
	}
}
extern "C" void* __shmem_grab(char* s,int l,void (__fastcall *init)(void *)) {
	return __shmem_winpthreads_grab(s,l,init);
}
BOOL WINAPI DllMain(HINSTANCE hinstDLL,DWORD fdwReason,LPVOID lpvReserved) {
	switch(fdwReason) {
		case DLL_PROCESS_ATTACH: {
			break;
		}
		case DLL_PROCESS_DETACH: {
			break;
		}
		case DLL_THREAD_ATTACH: {
			break;
		}
		case DLL_THREAD_DETACH: {
			break;
		}
	}

	/* Return TRUE on success, FALSE on failure */
	return TRUE;
}
