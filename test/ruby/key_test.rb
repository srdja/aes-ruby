
require 'test_helper'

require_relative '../../lib/ruby/aes.rb'

class KeyTest < Minitest::Test

  def test_invalid_key_size()
    assert_raises(ArgumentError) {AESKey.new([*1..10])}
    assert_raises(ArgumentError) {AESKey.new([*1..33])}
  end


  def test_128_bit_key_expansion()
    key_bytes = [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
                 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c]

    key = AESKey.new(key_bytes)

    assert_equal(0x2b7e1516, key.round_keys[0])
    assert_equal(0x28aed2a6, key.round_keys[1])
    assert_equal(0xabf71588, key.round_keys[2])
    assert_equal(0x09cf4f3c, key.round_keys[3])

    assert_equal(0xa0fafe17, key.round_keys[4])
    assert_equal(0x88542cb1, key.round_keys[5])
    assert_equal(0xf2c295f2, key.round_keys[8])
    assert_equal(0xca0093fd, key.round_keys[27])
    assert_equal(0xb6630ca6, key.round_keys[43])
  end


  def test_192_bit_key_expansion()
    key_bytes = [0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52,
                 0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5,
                 0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b]

    key = AESKey.new(key_bytes)

    assert_equal(0x8e73b0f7, key.round_keys[0])
    assert_equal(0xda0e6452, key.round_keys[1])
    assert_equal(0xc810f32b, key.round_keys[2])
    assert_equal(0x809079e5, key.round_keys[3])
    assert_equal(0x62f8ead2, key.round_keys[4])
    assert_equal(0x522c6b7b, key.round_keys[5])

    assert_equal(0xfe0c91f7, key.round_keys[6])
    assert_equal(0x5c56fec2, key.round_keys[11])
    assert_equal(0x4db7b4bd, key.round_keys[12])
    assert_equal(0xbc3ce7b5, key.round_keys[47])
    assert_equal(0xe98ba06f, key.round_keys[48])
    assert_equal(0x01002202, key.round_keys[51])
  end


  def test_256_bit_key_expansion()
    key_bytes = [0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
                 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
                 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
                 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4]

    key = AESKey.new(key_bytes)

    assert_equal(0x603deb10, key.round_keys[0])
    assert_equal(0x15ca71be, key.round_keys[1])
    assert_equal(0x2b73aef0, key.round_keys[2])
    assert_equal(0x857d7781, key.round_keys[3])
    assert_equal(0x1f352c07, key.round_keys[4])
    assert_equal(0x3b6108d7, key.round_keys[5])
    assert_equal(0x2d9810a3, key.round_keys[6])
    assert_equal(0x0914dff4, key.round_keys[7])

    assert_equal(0x9ba35411, key.round_keys[8])
    assert_equal(0x8e6925af, key.round_keys[9])
    assert_equal(0xfe4890d1, key.round_keys[56])
    assert_equal(0xe6188d0b, key.round_keys[57])
  end

end
