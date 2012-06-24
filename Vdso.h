#ifndef VDSO_H_
#define VDSO_H_

#include <stdio.h>
#include <string>
using std::string;


/// @brief Extracts VDSO binary from memory and writes it to a temporary file
///
/// The temporary file will be deleted when the VdsoBinary object is destroyed.
class VdsoBinary
{
public:
    VdsoBinary ();
    ~VdsoBinary ();

    /// @brief Returns path to extracted binary, or empty string if something went wrong
    string Path () const;

private:
    FILE* outFile;
    string path;

    static void GetVdsoAddress (unsigned int& start, unsigned int& end);
};

#endif
