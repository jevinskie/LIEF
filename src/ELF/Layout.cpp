/* Copyright 2021 - 2024 R. Thomas
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
#include "Layout.hpp"
#include "LIEF/ELF/Binary.hpp"
#include "LIEF/ELF/Symbol.hpp"
#include "LIEF/ELF/Section.hpp"
#include "internal_utils.hpp"

#include <LIEF/iostream.hpp>

namespace LIEF {
namespace ELF {

bool Layout::is_strtab_shared_shstrtab() const {
  // Check if the .strtab is shared with the .shstrtab
  const size_t shstrtab_idx = binary_->header().section_name_table_idx();
  size_t strtab_idx = 0;

  const Section* symtab = binary_->get(Section::TYPE::SYMTAB);
  if (symtab == nullptr) {
    return false;
  }
  strtab_idx = symtab->link();

  bool is_shared = true;
  const size_t nb_sections = binary_->sections().size();
  is_shared = is_shared && strtab_idx > 0 && shstrtab_idx > 0;
  is_shared = is_shared && strtab_idx < nb_sections && shstrtab_idx < nb_sections;
  is_shared = is_shared && strtab_idx == shstrtab_idx;
  return is_shared;
}

size_t Layout::section_strtab_size() {
  // could be moved in the class base.
  if (!raw_strtab_.empty()) {
    return raw_strtab_.size();
  }

  if (is_strtab_shared_shstrtab()) {
    fprintf(stderr, "section_strtab_size() is_strtab_shared_shstrtab() => true\n");
    // The content of .strtab is merged with .shstrtab
    return 0;
  }

  vector_iostream raw_strtab;
  raw_strtab.write<uint8_t>(0);

  size_t offset_counter = raw_strtab.tellp();

  if (binary_->symtab_symbols_.empty()) {
    return 0;
  }

  size_t tmp = 0;
  for (const auto &[k, v] : strtab_name_map_) {
    fprintf(stderr, "section_strtab_size before opt strtab_name_map_[%zu] k: '%s' v: %zu\n", tmp, k.c_str(), v);
    ++tmp;
  }
  fprintf(stderr, "section_strtab_size() offset_counter begin: %zu\n", offset_counter);

  std::vector<std::string> symstr_opt = optimize(binary_->symtab_symbols_,
                      [] (const std::unique_ptr<Symbol>& sym) { return sym->name(); },
                      offset_counter, &strtab_name_map_);

  fprintf(stderr, "section_strtab_size() offset_counter end: %zu\n", offset_counter);
  tmp = 0;
  for (const auto &[k, v] : strtab_name_map_) {
    fprintf(stderr, "section_strtab_size after opt strtab_name_map_[%zu] k: '%s' v: %zu\n", tmp, k.c_str(), v);
    ++tmp;
  }
  fprintf(stderr, "section_strtab_size after opt symstr_opt[0]: '%s' symstr_opt[1]: '%s' symstr_opt[2]: '%s' symstr_opt[-1]: '%s' symstr_opt[-2]: '%s' symstr_opt[-3]: '%s'\n", symstr_opt.at(0).c_str(), symstr_opt.at(1).c_str(), symstr_opt.at(2).c_str(), symstr_opt.at(symstr_opt.size() - 1).c_str(), symstr_opt.at(symstr_opt.size() - 2).c_str(), symstr_opt.at(symstr_opt.size() - 3).c_str());


  for (const std::string& name : symstr_opt) {
    raw_strtab.write(name);
  }

  auto itr = strtab_name_map_.begin();
  std::advance(itr, strtab_name_map_.size() - 1);
  const auto tmp2 = itr->second;
  const auto null_idx = strtab_name_map_[""];
  fprintf(stderr, "raw_strtab.raw().size(): %zu offset_counter: %zu\n", raw_strtab.raw().size(), offset_counter);
  // fprintf(stderr, "raw_strtab[0...3]: 0x%02hhx 0x%02hhx 0x%02hhx raw_strtab[-3...-1]: 0x%02hhx 0x%02hhx 0x%02hhx raw_strtab[%zu]: 0x%02hhx 0x%02hhx 0x%02hhx\n", raw_strtab.raw().at(0), raw_strtab.raw().at(1), raw_strtab.raw().at(2), raw_strtab.raw().at(raw_strtab.raw().size() - 3), raw_strtab.raw().at(raw_strtab.raw().size() - 2), raw_strtab.raw().at(raw_strtab.raw().size() - 1), tmp2, raw_strtab.raw().at(tmp2 - 1), raw_strtab.raw().at(tmp2), raw_strtab.raw().at(tmp2 + 1));
  fprintf(stderr, "raw_strtab[0...3]: 0x%02hhx 0x%02hhx 0x%02hhx raw_strtab[-3...-1]: 0x%02hhx 0x%02hhx 0x%02hhx raw_strtab[%zu]: 0x%02hhx null_idx: %zu raw_strtab[%zu]: 0x%02hhx\n", raw_strtab.raw().at(0), raw_strtab.raw().at(1), raw_strtab.raw().at(2), raw_strtab.raw().at(raw_strtab.raw().size() - 3), raw_strtab.raw().at(raw_strtab.raw().size() - 2), raw_strtab.raw().at(raw_strtab.raw().size() - 1), tmp2, raw_strtab.raw().at(tmp2), null_idx, null_idx, raw_strtab.raw().at(null_idx));

  raw_strtab.move(raw_strtab_);
  return raw_strtab_.size();
}

size_t Layout::section_shstr_size() {
  if (!raw_shstrtab_.empty()) {
    // Already in the cache
    return raw_shstrtab_.size();
  }

  vector_iostream raw_shstrtab;

  // In the ELF format all the .str sections
  // start with a null entry.
  raw_shstrtab.write<uint8_t>(0);
  std::vector<std::string> sec_names;
  sec_names.reserve(binary_->sections_.size());
  std::transform(std::begin(binary_->sections_), std::end(binary_->sections_),
                 std::back_inserter(sec_names),
                 [] (const std::unique_ptr<Section>& s) {
                   return s->name();
                 });

  if (!binary_->symtab_symbols_.empty()) {
    if (binary_->get(Section::TYPE::SYMTAB) == nullptr) {
      sec_names.emplace_back(".symtab");
    }
    if (binary_->get(Section::TYPE::SYMTAB) == nullptr) {
      sec_names.emplace_back(".strtab");
    }
  }

  for (const Note& note : binary_->notes()) {
    const std::string& secname = note.section_name();
    if (secname.empty()) {
      continue;
    }

    if (const Section* sec = binary_->get_section(secname); sec == nullptr) {
      sec_names.push_back(secname);
    }
  }

  // First write section names
  size_t offset_counter = raw_shstrtab.tellp();
  fprintf(stderr, "section_shstr_size() offset_counter begin: %zu\n", offset_counter);
  std::vector<std::string> shstrtab_opt = optimize(sec_names, [] (const std::string& s) { return s; },
                      offset_counter, &shstr_name_map_);
  fprintf(stderr, "section_shstr_size() offset_counter end: %zu\n", offset_counter);


  for (const std::string& name : shstrtab_opt) {
    raw_shstrtab.write(name);
  }

  // Check if the .shstrtab and the .strtab are shared (optimization used by clang)
  // in this case, include the symtab symbol names
  if (!binary_->symtab_symbols_.empty() && is_strtab_shared_shstrtab()) {
    offset_counter = raw_shstrtab.tellp();
    fprintf(stderr, "section_shstr_size() is_strtab_shared_shstrtab() offset_counter begin: %zu\n", offset_counter);
    std::vector<std::string> symstr_opt = optimize(binary_->symtab_symbols_,
                       [] (const std::unique_ptr<Symbol>& sym) { return sym->name(); },
                       offset_counter, &shstr_name_map_);
    fprintf(stderr, "section_shstr_size() is_strtab_shared_shstrtab() offset_counter end: %zu\n", offset_counter);
    for (const std::string& name : symstr_opt) {
      raw_shstrtab.write(name);
    }
  }

  raw_shstrtab.move(raw_shstrtab_);
  return raw_shstrtab_.size();
}

}
}
