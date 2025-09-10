#pragma once
#include<math.h>
#include<iostream>
#include<cstring>
#include<time.h>
#include<chrono>
#include<random>
using namespace std;
#define abs fabsl
unsigned long long fpow48(unsigned long long p) {
	unsigned long long d=37;
	unsigned long long a=1;
	while(p) {
		if(p&1) {
			a=(a*d)&0x0000FFFFFFFFFFFFULL;
		}
		d=(d*d)&0x0000FFFFFFFFFFFFULL;
		p>>=1;
	}
	return a;
}
class drng {
	union {
		volatile long double o;
		volatile unsigned __int128 p;
	};
public:
	using result_type=unsigned long long;
	static unsigned long long min() {
		return 0;
	}
	static unsigned long long max(){
		return -1ULL;
	}
	static_assert(sizeof(long double)==16,"bad size");
	static_assert(sizeof(unsigned __int128)==16,"bad size");
	drng(unsigned long long seed=1145141919810LLU) : o(0.5) {
		//cout<<((unsigned long long) (p>>64))<<" "<<((unsigned long long) p)<<endl;
		unsigned long long t=seed*6364136223846793005LLU+1442695040888963407LLU;
		//p^=((unsigned __int128) t)<<48;
		//p^=fpow48(t);
		p^=t&0x7fffffffffffffffULL;
		o=o*2-1;
	}
	unsigned long long operator()() {
		//cout<<o<<endl;
		o=2*o*o-1;
		unsigned long long l=p;
		l+=0x9e3779b97f4a7c15ULL;
		l=(l ^ (l >> 30)) * 0xbf58476d1ce4e5b9ULL;
		l=(l ^ (l >> 27)) * 0x94d049bb133111ebULL;
		return l^(l>>31);
	}
};
void encrypt(char* data, const char* key, size_t length) {
	auto up=reinterpret_cast<const unsigned long long*>(key);
	drng r1(up[0]), r2(up[1]);
	auto dp=reinterpret_cast<unsigned long long*>(data);
	auto ns=(length+7)>>3;
	for(size_t i=0; i<ns; i++) {
		dp[i]^=r1()*998244353+r2()*1000000007;
	}
}
void testrnd() {
	drng r(1);
	auto a=std::chrono::steady_clock::now();
	for(int i=0; i<100000000; i++) {
		r();
	}
	auto b=std::chrono::steady_clock::now();
	long long p=std::chrono::duration_cast<std::chrono::milliseconds>(b-a).count();
	cout<<"drng 100000000 cost "<<p<<"ms"<<endl;
}
void testrndx() {
	drng r(1);
	uniform_int_distribution<> a(1,70);
	int cnt[71];
	memset(cnt,0,71*4);
	for(int i=0;i<10000000;i++){
		cnt[a(r)]++;
	}
	for(int i=1;i<71;i++) cout<<cnt[i]<<" ";
	cout<<endl;
}
void testmrnd() {
	mt19937 r(1);
	auto a=std::chrono::steady_clock::now();
	for(int i=0; i<100000000; i++) {
		r();
	}
	auto b=std::chrono::steady_clock::now();
	long long p=std::chrono::duration_cast<std::chrono::milliseconds>(b-a).count();
	cout<<"mrng 100000000 cost "<<p<<"ms"<<endl;
}
