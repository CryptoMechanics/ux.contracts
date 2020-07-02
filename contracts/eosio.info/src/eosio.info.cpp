#include <eosio/system.hpp>
#include <eosio.info/eosio.info.hpp>

namespace eosio {

ACTION info::addkeytype(const name key, std::string definition, const bool user)
{
  require_auth(_self);

  keytypes_table table(_self, _self.value);

  auto itr = table.find(key.value);
  check(itr == table.end(), "key already exists");

  table.emplace(_self, [&](auto& t) {
    t.key = key;
    t.definition = definition;
    t.user = user;
  });
}

ACTION info::updkeytype(const name key, std::string definition, const bool user)
{
  require_auth(_self);

  keytypes_table table(_self, _self.value);

  auto itr = table.find(key.value);
  check(itr != table.end(), "key not present");

  table.modify(*itr, _self, [&]( auto& t) {
    t.definition = definition;
    t.user = user;
  });
}

ACTION info::adduserver(const name user, const name verification_key)
{
  require_auth(_self);

  check(is_account(user), "no account for specified user");

  keytypes_table kt_table(_self, _self.value);
  auto kt_itr = kt_table.find(verification_key.value);
  check(kt_itr != kt_table.end(), "verification_key not permitted");
  check(!kt_itr->user, "verification_key is a user key");

  userverifs_table table(_self, _self.value);
  auto ckey = composite_key(user.value, verification_key.value);
  auto idx = table.get_index<"ckey"_n>();
  auto itr = idx.find(ckey);

  check(itr == idx.end(), "user verification already present");

  table.emplace(user, [&](auto& t) {
    t.id = table.available_primary_key();
    t.user = user;
    t.verification_key = verification_key;
    t.timestamp = current_time_point();
  });
}

ACTION info::deluserver(const name user, const name verification_key)
{
  require_auth(_self);

  check(is_account(user), "no account for specified user");

  keytypes_table kt_table(_self, _self.value);
  auto kt_itr = kt_table.find(verification_key.value);
  check(kt_itr != kt_table.end(), "verification_key not permitted");
  check(!kt_itr->user, "verification_key is a user key");

  userverifs_table table(_self, _self.value);
  auto ckey = composite_key(user.value, verification_key.value);
  auto idx = table.get_index<"ckey"_n>();
  auto itr = idx.find(ckey);

  check(itr != idx.end(), "user verification not present");

  idx.erase(itr);
}

ACTION info::setuserkey(const name user, const name key, const std::string memo)
{
  require_auth(user);

  check(is_account(user), "no account for specified user");

  check(memo.length() <= 1024, "memo exceeds permitted length of 1024 chars");

  keytypes_table kt_table(_self, _self.value);
  auto kt_itr = kt_table.find(key.value);
  check(kt_itr != kt_table.end(), "verification_key not recognised");

  userkeys_table table(_self, _self.value);
  auto ckey = composite_key(user.value, key.value);
  auto idx = table.get_index<"ckey"_n>();
  auto itr = idx.find(ckey);

  if (itr == idx.end()) {
    table.emplace(user, [&](auto& t) {
      t.id = table.available_primary_key();
      t.user = user;
      t.key = key;
      t.memo = memo;
    });
  } else {
    table.modify(*itr, user, [&]( auto& t) {
      t.memo = memo;
    });
  }
}

ACTION info::deluserkey(const name user, const name key)
{
  require_auth(user);

  check(is_account(user), "no account for specified user");

  userkeys_table table(_self, _self.value);
  auto ckey = composite_key(user.value, key.value);
  auto idx = table.get_index<"ckey"_n>();
  auto itr = idx.find(ckey);

  check(itr != idx.end(), "user key not present");

  idx.erase(itr);
}

void info::freezecode(const name account)
{
  // requires owner permission to freeze code
  require_auth(permission_level{account, name("owner")});

  frozen_table table(_self, _self.value);
  auto itr = table.find(account.value);

  check(itr == table.end(), "account already frozen");

  table.emplace(account, [&](auto &t) { t.account = account; });
}

} /// namespace eosio
