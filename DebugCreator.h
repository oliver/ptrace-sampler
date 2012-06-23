#ifndef DEBUG_CREATOR_H_
#define DEBUG_CREATOR_H_


#include "DebugInterpreter.h"

#include <string>
#include <vector>

using std::string;
using std::vector;


void CreateDebugInfo (DI::DebugTable& debugTable,
                      const string& binPath,
                      const unsigned int mapAddress,
                      const vector<string>& functions);

#endif
