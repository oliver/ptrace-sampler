#ifndef DEBUG_CREATOR_H_
#define DEBUG_CREATOR_H_


#include "DebugInterpreter.h"

#include <string>

using std::string;


/// Create debug information for all functions in this binary which use FPO
void CreateDebugInfo (DI::DebugTable& debugTable,
                      const string& binPath,
                      const unsigned int mapAddress);

#endif
