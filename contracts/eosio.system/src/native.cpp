#include <eosio.system/native.hpp>

#include <eosio/check.hpp>
#include <eosio.info/eosio.info.hpp>

namespace eosiosystem {

   void native::onerror( ignore<uint128_t>, ignore<std::vector<char>> ) {
      eosio::check( false, "the onerror action cannot be called directly" );
   }

   void native::setcode( const name& account, uint8_t vmtype, uint8_t vmversion, const std::vector<char>& code ) {
      // requires FORWARD_SETCODE protocol feature 2652f5f96006294109b3dd0bbde63693f55324af452b799ee137a81a905eed25
      eosio::info::frozen_table table(name("eosio.info"), name("eosio.info").value);
      eosio::check(table.find(account.value) == table.end(), "code updates for this account have been frozen");
   }
}
