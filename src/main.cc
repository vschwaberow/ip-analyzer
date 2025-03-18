// SPDX-License-Identifier: MIT
// Project: ip-analyzer
// File: src/main.cc
// Author: Volker Schwaberow <volker@schwaberow.de>
// Copyright (c) 2024 Volker Schwaberow

#include "cli_app.hh"
#include <span>

using namespace ip_analyzer;

int main(int argc, char* argv[])
{
    return IPAnalyzerApp().Run(std::span(argv, static_cast<size_t>(argc)));
}