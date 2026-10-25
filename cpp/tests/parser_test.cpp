#include "uidai/core/parser.h"

#include "test_util.h"

#include <string>

using uidai::core::AttrParser;
using uidai::core::QueryParser;

TEST(query_parser_extracts_params) {
  QueryParser q("/request?stage=staging&request=otp&otp={uid=1}");
  CHECK_EQ(*q.param("request"), std::string("otp"));
  CHECK_EQ(*q.param("stage"), std::string("staging"));
  CHECK_EQ(*q.param("otp"), std::string("{uid=1}"));
  CHECK(!q.param("missing").has_value());
}

TEST(query_parser_without_question_mark) {
  QueryParser q("a=1&b=2");
  CHECK_EQ(*q.param("b"), std::string("2"));
}

TEST(query_parser_last_segment) {
  QueryParser q("a=1&b=");
  CHECK_EQ(*q.param("b"), std::string(""));
}

TEST(attr_parser_extracts_attrs) {
  AttrParser a("{uid=999938452218,tid=public,ver=1.6}");
  CHECK_EQ(*a.attr("uid"), std::string("999938452218"));
  CHECK_EQ(*a.attr("tid"), std::string("public"));
  CHECK_EQ(*a.attr("ver"), std::string("1.6"));
  CHECK(!a.attr("nope").has_value());
}

TEST(attr_parser_empty_value) {
  AttrParser a("{tid=,name=x}");
  CHECK_EQ(*a.attr("tid"), std::string(""));
  CHECK_EQ(*a.attr("name"), std::string("x"));
}
