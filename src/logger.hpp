//
// Created by Archer on 4/16/2021.
//

#ifndef PANDA_LOGGER_HPP
#define PANDA_LOGGER_HPP

#include <Windows.h>
#include <string>
#include <sstream>

struct logger
{
    explicit logger( const std::string& filepath );
    ~logger();

    template<typename... Tx>
    void log( const char* fmt, Tx&&... args )
    {
        std::string buffer;
        buffer.resize( snprintf( nullptr, 0, fmt, args... ) );
        snprintf( buffer.data(), buffer.size() + 1, fmt, std::forward<Tx>( args )... );

        WriteFile( h_log_file, buffer.c_str(), buffer.size(), nullptr, nullptr );
    }

private:
    HANDLE h_log_file = nullptr;
};

static logger* writer = nullptr;

logger* get_logger();
logger* get_logger( const std::string& filepath );


#endif //PANDA_LOGGER_HPP
