#include <boost/context/continuation.hpp>

#include <utility>

int main() {
    namespace ctx = boost::context;

    int value = 0;
    ctx::continuation source = ctx::callcc([&value](ctx::continuation&& sink) {
        value = 42;
        return std::move(sink);
    });

    return value == 42 ? 0 : 1;
}
