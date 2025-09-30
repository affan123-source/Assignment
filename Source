#include <cstdio>
#include <cstdint>
#include <vector>
#include <array>
#include <string>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <stdexcept>
#include <algorithm>

static bool isHex(char c){return (c>='0'&&c<='9')||(c>='a'&&c<='f')||(c>='A'&&c<='F')||(c=='x'||c=='X');}
static uint8_t hexVal(char c){if(c>='0'&&c<='9')return c-'0'; if(c>='a'&&c<='f')return 10+(c-'a'); if(c>='A'&&c<='F')return 10+(c-'A'); return 0;}
static std::vector<uint8_t> parseHex(const std::string& s){std::vector<uint8_t> out; int n1=-1; for(char c: s){if(!isHex(c))continue; if(c=='x'||c=='X')continue; int v=hexVal(c); if(n1<0)n1=v; else{out.push_back((uint8_t)((n1<<4)|v)); n1=-1;}} if(n1!=-1) throw std::runtime_error("odd hex length"); if(out.empty()) throw std::runtime_error("empty hex"); return out;}
static std::string toHex(const std::vector<uint8_t>& v){std::ostringstream o; o<<std::hex<<std::setfill('0'); for(size_t i=0;i<v.size();++i){o<<std::setw(2)<<(unsigned)v[i]; if(i+1<v.size()) o<<' ';} return o.str();}
static std::string toHex(const uint8_t* p,size_t n){return toHex(std::vector<uint8_t>(p,p+n));}
static void printKV(const std::string& k,const std::string& v){std::cout<<std::left<<std::setw(28)<<k<<": "<<v<<"\n";}

struct AES128{
    uint8_t rk[176];
    static uint8_t rcon(uint8_t i){static const uint8_t rc[11]={0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1B,0x36}; return rc[i];}
    static uint8_t sbox(uint8_t x){static const uint8_t s[256]={
        0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
        0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
        0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
        0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
        0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
        0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
        0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
        0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
        0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
        0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
        0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
        0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
        0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
        0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
        0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
        0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16};
        return s[x];
    }
    static uint8_t invsbox(uint8_t x){static const uint8_t s[256]={
        0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
        0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
        0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
        0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
        0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
        0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
        0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
        0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
        0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
        0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
        0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
        0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
        0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
        0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
        0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
        0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d};
        return s[x];
    }
    static uint8_t gmul(uint8_t a,uint8_t b){uint8_t p=0; for(int i=0;i<8;++i){if(b&1)p^=a; uint8_t hi=a&0x80; a<<=1; if(hi)a^=0x1b; b>>=1;} return p;}
    void keyExpansion(const uint8_t key[16]){
        for(int i=0;i<16;++i) rk[i]=key[i];
        int bytes=16; int rconIter=1; uint8_t t[4];
        while(bytes<176){
            for(int i=0;i<4;++i) t[i]=rk[bytes-4+i];
            if(bytes%16==0){
                uint8_t tmp=t[0]; t[0]=t[1]; t[1]=t[2]; t[2]=t[3]; t[3]=tmp;
                t[0]=sbox(t[0]); t[1]=sbox(t[1]); t[2]=sbox(t[2]); t[3]=sbox(t[3]);
                t[0]^=rcon(rconIter++);
            }
            for(int i=0;i<4;++i){ rk[bytes]=rk[bytes-16]^t[i]; ++bytes; }
        }
    }
    void invShiftRows(uint8_t s[16]){uint8_t t; t=s[13]; s[13]=s[9]; s[9]=s[5]; s[5]=s[1]; s[1]=t; t=s[2]; s[2]=s[10]; s[10]=t; t=s[6]; s[6]=s[14]; s[14]=t; t=s[3]; s[3]=s[7]; s[7]=s[11]; s[11]=s[15]; s[15]=t;}
    void invSubBytes(uint8_t s[16]){for(int i=0;i<16;++i)s[i]=invsbox(s[i]);}
    void addRoundKey(uint8_t s[16],const uint8_t* rkx){for(int i=0;i<16;++i)s[i]^=rkx[i];}
    void invMixColumns(uint8_t s[16]){
        for(int c=0;c<4;++c){
            uint8_t a0=s[4*c+0],a1=s[4*c+1],a2=s[4*c+2],a3=s[4*c+3];
            s[4*c+0]=gmul(a0,0x0e)^gmul(a1,0x0b)^gmul(a2,0x0d)^gmul(a3,0x09);
            s[4*c+1]=gmul(a0,0x09)^gmul(a1,0x0e)^gmul(a2,0x0b)^gmul(a3,0x0d);
            s[4*c+2]=gmul(a0,0x0d)^gmul(a1,0x09)^gmul(a2,0x0e)^gmul(a3,0x0b);
            s[4*c+3]=gmul(a0,0x0b)^gmul(a1,0x0d)^gmul(a2,0x09)^gmul(a3,0x0e);
        }
    }
    void decryptBlock(const uint8_t in[16],uint8_t out[16]){
        uint8_t s[16]; for(int i=0;i<16;++i)s[i]=in[i];
        addRoundKey(s,rk+160);
        for(int r=9;r>=1;--r){invShiftRows(s); invSubBytes(s); addRoundKey(s,rk+16*r); invMixColumns(s);}
        invShiftRows(s); invSubBytes(s); addRoundKey(s,rk);
        for(int i=0;i<16;++i) out[i]=s[i];
    }
};

static size_t findCI(const std::vector<uint8_t>& f){for(size_t i=0;i<f.size();++i){uint8_t b=f[i]; if((b==0x7A||b==0x72) && i>=8) return i;} throw std::runtime_error("CI not found");}
struct TplShortHeader{uint8_t acc,status,cfg_l,cfg_h; uint8_t security_mode()const{return (uint8_t)(cfg_h&0x0F);} };
static TplShortHeader readTplShortHeader(const std::vector<uint8_t>& f,size_t ci){if(ci+4>=f.size()) throw std::runtime_error("TPL header out of range"); return TplShortHeader{f[ci+1],f[ci+2],f[ci+3],f[ci+4]};}
static std::array<uint8_t,8> extractAField(const std::vector<uint8_t>& f,size_t ci){if(ci<8) throw std::runtime_error("A-Field missing"); std::array<uint8_t,8>a{}; for(int i=0;i<8;++i)a[i]=f[ci-8+i]; return a;}
static std::array<uint8_t,16> buildIV_OMS5(const std::array<uint8_t,8>& a,uint8_t acc){std::array<uint8_t,16> iv{}; for(int i=0;i<8;++i)iv[i]=a[i]; for(int i=8;i<16;++i)iv[i]=acc; return iv;}
static std::array<uint8_t,16> buildIV_Compat(const std::vector<uint8_t>& f,size_t ci){
    std::array<uint8_t,16> iv{}; if(ci<11) throw std::runtime_error("too short for compat IV");
    for(int i=0;i<8;++i) iv[i]=f[ci-11+i];
    for(int i=8;i<16;++i) iv[i]=0x20;
    return iv;
}
static std::vector<uint8_t> extractCiphertext(const std::vector<uint8_t>& f,size_t ci){
    size_t start=ci+5; if(start>=f.size()) throw std::runtime_error("No ciphertext");
    std::vector<uint8_t> tail(f.begin()+start,f.end());
    if(tail.size()%16!=0){ if(tail.size()>=2 && (tail.size()-2)%16==0) tail.resize(tail.size()-2); }
    if(tail.size()%16!=0) tail.resize((tail.size()/16)*16);
    if(tail.empty()) throw std::runtime_error("Ciphertext invalid size");
    return tail;
}
static std::vector<uint8_t> aes128cbc_decrypt(const std::vector<uint8_t>& ct,const std::array<uint8_t,16>& key,const std::array<uint8_t,16>& iv){
    AES128 aes; aes.keyExpansion(key.data());
    std::vector<uint8_t> pt(ct.size()); std::array<uint8_t,16> prev=iv;
    for(size_t off=0; off<ct.size(); off+=16){
        uint8_t out[16]; aes.decryptBlock(&ct[off],out);
        for(int i=0;i<16;++i) pt[off+i]=out[i]^prev[i];
        for(int i=0;i<16;++i) prev[i]=ct[off+i];
    }
    return pt;
}
static std::vector<uint8_t> stripFillers(const std::vector<uint8_t>& in){size_t s=0,e=in.size(); if(in.size()>=2&&in[0]==0x2F&&in[1]==0x2F) s=2; while(e>s&&in[e-1]==0x2F) --e; return std::vector<uint8_t>(in.begin()+s,in.begin()+e);}

int main(int argc,char** argv){
    try{
        std::string keyHex="4255794d3dccfd46953146e701b7db68";
        std::string msgHex=
            "a144c5142785895070078c20607a9d00902537ca231fa2da5889be8df367"
            "3ec136aebfb80d4ce395ba98f6b3844a115e4be1b1c9f0a2d5ffbb92906aa388deaa"
            "82c929310e9e5c4c0922a784df89cf0ded833be8da996eb5885409b6c9867978dea"
            "24001d68c603408d758a1e2b91c42ebad86a9b9d287880083bb0702850574d7b51"
            "e9c209ed68e0374e9b01febfd92b4cb9410fdeaf7fb526b742dc9a8d0682653";
        std::string ivMode="oms";
        for(int i=1;i<argc;++i){
            std::string a=argv[i];
            if(a.rfind("--key=",0)==0) keyHex=a.substr(6);
            else if(a.rfind("--tele=",0)==0) msgHex=a.substr(7);
            else if(a.rfind("--iv=",0)==0) ivMode=a.substr(5);
        }

        auto frame=parseHex(msgHex);
        auto keyV=parseHex(keyHex); if(keyV.size()!=16) throw std::runtime_error("key must be 16 bytes");
        std::array<uint8_t,16> key{}; std::copy(keyV.begin(),keyV.end(),key.begin());
        size_t ci=findCI(frame);
        auto a=extractAField(frame,ci);
        auto tpl=readTplShortHeader(frame,ci);
        if(tpl.security_mode()!=5) throw std::runtime_error("unsupported security mode");
        std::array<uint8_t,16> iv = (ivMode=="compat") ? buildIV_Compat(frame,ci) : buildIV_OMS5(a,tpl.acc);
        auto ct=extractCiphertext(frame,ci);
        auto pt=aes128cbc_decrypt(ct,key,iv);
        auto ptClean=stripFillers(pt);

        std::ostringstream ciVal; ciVal<<"0x"<<std::hex<<std::setfill('0')<<std::setw(2)<<(unsigned)frame[ci];
        std::cout<<"OMS/WMBus Decryption Result\n";
        printKV("CI index",std::to_string(ci));
        printKV("CI value",ciVal.str());
        printKV("A-Field",toHex(a.data(),8));
        {std::ostringstream accs; accs<<"0x"<<std::hex<<std::setfill('0')<<std::setw(2)<<(unsigned)tpl.acc; printKV("Access Number (ACC)",accs.str());}
        printKV("Security Mode",std::to_string((unsigned)tpl.security_mode()));
        printKV("IV mode",ivMode=="compat"?"compat":"oms");
        printKV("IV",toHex(iv.data(),16));
        printKV("Ciphertext",toHex(ct));
        printKV("Plaintext (raw)",toHex(pt));
        printKV("Plaintext (trimmed)",toHex(ptClean));
        if(!ptClean.empty()){
            std::cout<<"Parsed (best-effort)\n";
            if(ptClean.size()>=1) printKV("DIF",toHex(ptClean.data(),1));
            if(ptClean.size()>=2) printKV("VIF",toHex(ptClean.data()+1,1));
            if(ptClean.size()>2){ std::vector<uint8_t> val(ptClean.begin()+2,ptClean.end()); printKV("Value bytes",toHex(val));}
        }
        return 0;
    }catch(const std::exception& ex){
        std::cerr<<"ERROR: "<<ex.what()<<"\n";
        return 1;
    }
}




