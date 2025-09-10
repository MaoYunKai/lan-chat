/* Replace "dll.h" with the name of your header */
#include "jit.h"
#include <windows.h>
#include <Python.h>
#include <algorithm>
#include <iostream>
#include <string>
#include <functional>
#include <math.h>
using namespace std;
#define import_py_mod(func,rfunc) func = (decltype(func)) GetProcAddress(pPyModule, #rfunc);
class PyDllLoader {
	HMODULE pPyModule;
public:
	PyObject* (*PyModuleCreate)(PyModuleDef*, int);
	PyObject* (*PyBuildValue)(const char*, ...);
	int (*PyArgParseTuple)(PyObject*, const char*, ...);
	PyDllLoader() {
		pPyModule = LoadLibrary("python311.dll");
		import_py_mod(PyModuleCreate,PyModule_Create2);
		import_py_mod(PyBuildValue,Py_BuildValue);
		import_py_mod(PyArgParseTuple,PyArg_ParseTuple);
	}
} gldr;
#define ui unsigned int
#define ul unsigned long long
#define ulll unsigned __int128
#define popcnt __builtin_popcount
#define popcntl __builtin_popcountll
#define popcntlll(x) (popcntl((x)>>64) + popcntl(x))
inline __attribute__((always_inline))
pair<ui,ui> encrypt(ui y,ui z,ui k0,ui k1,ui k2,ui k3) {
	ui delta=0x9e3779b9U;
	ui s=0xC6EF3720U;
	for(int i=0; i<32; i++) {
		y-=((z<<4)+k0)^(z+s)^((z>>5)+k1);
		z-=((y<<4)+k2)^(y+s)^((y>>5)+k3);
		s+=0x61C88647U;
	}
	return pair<ui,ui> {y,z};
}
#define e(x) ((ulll) x##ULL)
inline __attribute__((always_inline))
ui sdh_hash0(ui a,ui b,ui sk0,ui sk1,ui sk2,ui sk3) {
	ui q1=a*1998244349U+0x9e3779b9U+(b<<6)+(b>>2);
	ui q2=b*1998244349U+0x9e3779b9U+(a<<6)+(a>>2);
	ui m,n,u,v;
	tie(m,n)=encrypt(q1,q2,sk0,sk1,sk2,sk3);
	tie(u,v)=encrypt(0x9d2c5680U,0xEDB88320U,sk0,sk1,sk2,sk3);
	ui fchk0=0;
	ui fchk1=0;
	ui fs[2]= {m+u,n+v};
	ui bkey=37;
	for(int i=0; i<16; i++) {
		tie(fchk0,fchk1)=encrypt(fs[0],fs[1],0xb5026f5aU,fchk0,fchk1,0xa96619e9U);
		fs[0]+=0x9e3779b9U+(fchk0<<6)+(fchk1>>2);
		fs[1]+=0x9e3779b9U+(fchk1<<6)+(fchk0>>2);
		bkey^=popcnt(fs[0])+popcnt(fs[1]);
	}
	ui nv_chk0,nv_chk1;
	tie(nv_chk0,nv_chk1)=encrypt(1566083941,19780503,fchk0,fs[1],fs[0],fchk1);
	ulll nv_chk=nv_chk0*e(341873128712)+nv_chk1*e(132897987541);
	nv_chk += popcntlll(nv_chk)*e(0x4d595df4d0f33173);
	nv_chk&=e(0xffffffffffffffff);
	nv_chk=(nv_chk+1442695040888963407)^
	       (((m*e(341873128712)+
	          v*e(132897987541))^
	         (u*e(314159)+
	          n*e(1000003)))*e(6364136223846793005)+
	        e(0x9e3779b97f4a7c15)+(nv_chk<<bkey)+(nv_chk>>(64-bkey)));
	nv_chk += popcntlll(nv_chk)*e(0x4d595df4d0f33173);
	nv_chk&=e(0xffffffffffffffff);
	nv_chk=(nv_chk+e(1442695040888963407))^
	       (((u*e(341873128712)+
	          n*e(132897987541))^
	         (m*e(314159)+v*e(1000003)))*e(6364136223846793005)+
	        e(0x9e3779b97f4a7c15)+(nv_chk<<bkey)+(nv_chk>>(64-bkey)));
	nv_chk += popcntlll(nv_chk)*e(0x4d595df4d0f33173);
	nv_chk&=e(0xffffffffffffffff);
	nv_chk=(nv_chk^(nv_chk>>30))*e(0xbf58476d1ce4e5b9);
	nv_chk=(nv_chk^(nv_chk>>27))*e(0x94d049bb133111eb);
	nv_chk^=nv_chk>>31;
	return nv_chk;
}
PyObject* py_sdh_hash0(PyObject* self, PyObject* args) {
	ui a,b,c,d,e,f;
	if(!gldr.PyArgParseTuple(args,"IIIIII",&a,&b,&c,&d,&e,&f)) {
		return NULL;
	}
	ui result = sdh_hash0(a,b,c,d,e,f);
	return gldr.PyBuildValue("I",result);
}
PyObject* calc_expected_pktsize(PyObject* self, PyObject* args) {
	int rssi;
	if(!gldr.PyArgParseTuple(args,"I",&rssi)) {
		return NULL;
	}
	static int noise_floor = -80;
	long double snr=rssi-noise_floor;
	long double snr_linear=powl(10,snr/10)/4;
	long double ber=erfcl(sqrtl(snr_linear))/2;
	long double s = 20/ber;
	if(s<64) s=64;
	if(s>1280) s=1280;
	ui result = s+0.5;
	result &= -8;
	return gldr.PyBuildValue("I",result);
}
inline __attribute__((always_inline))
ui fpow32(ui x,ui y) {
	ui result=1;
	while(y) {
		if(y&1) result *= x;
		x *= x;
		y>>=1;
	}
	return result;
}
inline __attribute__((always_inline))
void calcxyzyz(ui nv_chk, ul key, ul key2, ui& x, ui& y, ui& z, ui& y2, ui& z2) {
	x=((nv_chk^1000000007U)*998244353U)^((nv_chk^999999937U)*0x9908b0dfU);
	x+=fpow32(37,popcnt(nv_chk));
	y=key+nv_chk;
	z=(key>>32)+nv_chk;
	ui chk2=fpow32(16807,key)^fpow32(48271,key>>32);
	y2=key2+chk2;
	z2=(key2>>32)+chk2;
}
PyObject* py_calcxyzyz(PyObject* self, PyObject* args) {
	unsigned int a;
	unsigned long long b,c;
	if(!gldr.PyArgParseTuple(args,"IKK",&a,&b,&c)) {
		return NULL;
	}
	unsigned int d,e,f,g,h;
	calcxyzyz(a,b,c,d,e,f,g,h);
	return gldr.PyBuildValue("(IIIII)",d,e,f,g,h);
}
inline __attribute__((always_inline))
void t64(ul k0,ul k1,ul k2,ul k3, ul& y, ul& z) {
	y = e(0x4d595df4d0f33173);
	z = e(0xbf58476d1ce4e5b9);
	ul delta = e(0x9e3779b97f4a7c15);
	ul s = e(0x8dde6e5fd29f0540);
	for(int i=0; i<64; i++) {
		y -= ((z << 16) + k0) ^ (z + s) ^ ((z >> 17) + k1);
		z -= ((y << 16) + k2) ^ (y + s) ^ ((y >> 17) + k3);
		s += e(0x61c8864680b583eb);
	}
}
PyObject* py_t64(PyObject* self, PyObject* args) {
	ul a,b,c,d;
	if(!gldr.PyArgParseTuple(args,"KKKK",&a,&b,&c,&d)) {
		return NULL;
	}
	ul e,f;
	t64(a,b,c,d,e,f);
	return gldr.PyBuildValue("(KK)",e,f);
}
PyMethodDef methods[] = {
	{"sdh_hash0", py_sdh_hash0,METH_VARARGS, "sdh_hash0(a,b,*sk[4])->nv_chk"},
	{"calc_expected_pktsize",calc_expected_pktsize,METH_VARARGS, "calc(rssi)->pktsize"},
	{"calcxyzyz",py_calcxyzyz,METH_VARARGS,"calcxyzyz(nv_chk,key,key2)->(x,y,z,y2,z2)"},
	{"t64",py_t64,METH_VARARGS,"t64(*k[4])->(y,z)"},
	{NULL,NULL,0,NULL}
};
PyModuleDef modu = {
	PyModuleDef_HEAD_INIT,
	"jit",
	NULL,
	-1,
	methods
};
extern "C"
__declspec(dllexport)
PyObject* PyInit_jit() {
	return gldr.PyModuleCreate(&modu, PYTHON_API_VERSION);
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
