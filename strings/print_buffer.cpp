#include <iostream>
#include <memory>
#include <cstring>
#include <cstdio>

class PrintBuffer {
public:
    PrintBuffer(int buffer_size) : buffer_size(buffer_size), space_used(0), buffer(std::make_unique<char[]>(buffer_size)) {}

    virtual ~PrintBuffer() {
        flush();
    }

    void addString(const char* string) {
        int length = std::strlen(string);
        addString(string, length);
    }

    void addStrings(const char* strings[]) {
        for (int i = 0; strings[i] != nullptr; ++i)
            addString(strings[i]);
    }

    virtual void addString(const char* string, int length) {
        if (space_used + length >= buffer_size)
            flush();

        if (length >= buffer_size) {
            std::fwrite(string, length, 1, stdout);
            std::fflush(stdout);
        }
        else {
            std::memcpy(buffer.get() + space_used, string, length);
            space_used += length;
            buffer[space_used] = '\0';
        }
    }

    virtual void addLine(const char* string) {
        addString(string, std::strlen(string));
        addString("\r\n", 2);
    }

    virtual void flush() {
        if (space_used > 0) {
            std::fwrite(buffer.get(), 1, space_used, stdout);
            std::fflush(stdout);
            space_used = 0;
        }
    }

protected:
    int buffer_size;
    int space_used;
    std::unique_ptr<char[]> buffer;
};

class BufferedPrinter : public PrintBuffer {
public:
    BufferedPrinter(int buffer_size) : PrintBuffer(buffer_size) {}

    void addString(const char* string, int length) override {
        PrintBuffer::addString(string, length);
        if (space_used >= buffer_size / 2)
            flush();
    }

    void addLine(const char* string) override {
        PrintBuffer::addLine(string);
        if (space_used >= buffer_size / 2)
            flush();
    }
};
