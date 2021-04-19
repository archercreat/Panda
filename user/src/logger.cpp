//
// Created by Archer on 4/16/2021.
//

#include "logger.hpp"

logger::logger( const std::string& filepath )
{
    h_log_file = CreateFile( filepath.c_str(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr );
}

logger::~logger()
{
    CloseHandle( h_log_file );
}

logger* get_logger( const std::string& filepath )
{
    if ( writer == nullptr )
    {
        writer = new logger( filepath );
    }
    return writer;
}

logger* get_logger()
{
    return writer;
}