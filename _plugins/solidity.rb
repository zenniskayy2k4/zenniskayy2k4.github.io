require 'rouge'

module Rouge
  module Lexers
    class Solidity < RegexLexer
      title "Solidity"
      desc "The Solidity smart contract language"
      tag 'solidity'
      filenames '*.sol'

      mimetypes 'text/x-solidity'

      def self.keywords
        @keywords ||= %w(
          pragma contract function modifier event struct mapping enum import
          return returns if else for while do break continue throw revert require
          public private internal external constant view pure payable
          storage memory calldata
          uint uint8 uint16 uint32 uint64 uint128 uint256 int int8 int16 int32
          address bool string bytes bytes1 bytes32
        )
      end

      state :root do
        rule %r(/\*.*?\*/), Comment::Multiline
        rule %r(//.*?$), Comment::Single
        rule %r('.*?'|".*?"), Str::Double
        rule %r(\b(?:#{Regexp.union(Rouge::Lexers::Solidity.keywords).source})\b), Keyword
        rule %r(\b0x[0-9a-fA-F]+\b), Num::Hex
        rule %r(\b\d+\b), Num::Integer
        rule %r([{}();,.<>=:+\-*/%!&|^~\[\]]), Punctuation
        rule %r([A-Za-z_]\w*), Name
        rule %r(\s+), Text
      end
    end
  end
end
