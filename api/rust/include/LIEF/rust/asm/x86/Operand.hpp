/* Copyright 2022 - 2024 R. Thomas
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#pragma once
#include "LIEF/asm/x86/Operand.hpp"

#include "LIEF/rust/Mirror.hpp"

class asm_x86_Operand : public Mirror<LIEF::assembly::x86::Operand> {
  public:
  using lief_t = LIEF::assembly::x86::Operand;
  using Mirror::Mirror;

  std::string to_string() const {
    return get().to_string();
  }
};
