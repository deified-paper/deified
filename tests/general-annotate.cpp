#include <cstdlib>
#include <cstring>
#include <iostream>
#include <memory>
#include <string>
#include <utility>

#define HQ_ANNOTATE __attribute__((aligned(8), annotate("hq")))

class Wrapper {
  public:
    HQ_ANNOTATE bool wb;

    // Explicitly declare constructor to prevent automatic zeroing and elision
    Wrapper() : wb() {}
};

class Primitive {
  public:
    HQ_ANNOTATE char la[16];
    HQ_ANNOTATE bool lb;
    HQ_ANNOTATE unsigned lu;
    HQ_ANNOTATE float lf;
    HQ_ANNOTATE double ld;

    ~Primitive() {
        memset(la, 0, sizeof(la));
        lb = 0;
        lu = 0;
        lf = 0;
        ld = 0;
    }

    const char *const getCharArray() const { return la; }
    void setCharArray(const char *s) {
        memcpy(la, s, std::min(strlen(s) + 1, sizeof(la) - 1));
    }
    bool getBool() const { return lb; }
    void setBool(bool b) { lb = b; }
    unsigned getUnsigned() const { return lu; }
    void setUnsigned(unsigned u) { lu = u; }
    float getFloat() const { return lf; }
    void setFloat(float f) { lf = f; }
    double getDouble() const { return ld; }
    void setDouble(double d) { ld = d; }
};

Wrapper gw;

// Test for primitive types
void __attribute__((noinline))
primitive(bool b, unsigned u, float f, double d) {
    Primitive p1, *p2 = new Primitive();

    // Store
    // strcpy does not have readonly/writeonly annotations
    p1.setCharArray("array");
    p1.setBool(b);
    p1.setUnsigned(u);
    p1.setFloat(f);
    p1.setDouble(d);

    memcpy(p2->la, "array", sizeof("array"));
    p2->lb = b;
    p2->lu = u;
    p2->lf = f;
    p2->ld = d;

    // Load
    printf("p1: array: %s, bool: %d, unsigned: %u, float: %f, double: %f\n",
           p1.getCharArray(), p1.getBool(), p1.getUnsigned(), p1.getFloat(),
           p1.getDouble());
    printf("p2: array: %s, bool: %d, unsigned: %u, float: %f, double: %f\n",
           p2->la, p2->lb, p2->lu, p2->lf, p2->ld);
    delete p2;
}

class Complex {
  public:
    HQ_ANNOTATE std::string ls;
    HQ_ANNOTATE std::unique_ptr<std::string> lup;
    HQ_ANNOTATE std::shared_ptr<std::string> lsp;
    HQ_ANNOTATE std::pair<int, std::string> lp;
};

// Test for complex types
void __attribute__((noinline)) complex() {
    Complex c1, *c2 = new Complex();

    // Store
    c1.ls = "string";
    c1.lup = std::make_unique<std::string>("unique");
    c1.lsp = std::make_shared<std::string>("shared");
    c1.lp = std::make_pair<>(42, "pair");
    c2->ls = "string";
    c2->lup = std::make_unique<std::string>("unique");
    c2->lsp = std::make_shared<std::string>("shared");
    c2->lp = std::make_pair<>(42, "pair");

    // Load
    printf("c1: string: %s, unique: %s, shared: %s, pair: <%d, %s>\n",
           c1.ls.c_str(), c1.lup->c_str(), c1.lsp->c_str(), c1.lp.first,
           c1.lp.second.c_str());
    printf("c2: string: %s, unique: %s, shared: %s, pair: <%d, %s>\n",
           c2->ls.c_str(), c2->lup->c_str(), c2->lsp->c_str(), c2->lp.first,
           c2->lp.second.c_str());
    delete c2;
}

void __attribute__((noinline)) corrupt() {
    *((uintptr_t *)&gw) = (uintptr_t)&gw;
}

int main(int argc, char **argv) {
    printf("Test: Primitive types\n");
    primitive(true, 42u, 2.3f, 4.8);

    printf("Test: Complex types\n");
    complex();

    printf("Test: Corrupt\n");
    corrupt();
    printf("This message should NOT be displayed: %d!", gw.wb);
    return 0;
}
