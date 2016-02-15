
# Cipher Block Chaining  mode
#
# Plain text blocks are XORed with the previous block's cipher text, however the
# first block requires a random IV to be XORed with since there is no previous
# cipher text block.
class AES_CBC

  def initialize(cipher)
    @cipher = cipher
  end


  # XORs the first buffer with the second and store
  def xor_buffer(b1, b2)
    rb = []
    (0..15).each do |i|
      rb[i] = b1[i] ^ b2[i]
    end
    rb
  end


  def encrypt(msg, key, iv, add_padding)
    b_size = @cipher.block_size
    block_offset = msg.length % b_size

    # Add padding
    if add_padding
      padding = (block_offset == 0) ? 15 : (block_offset - 1)

      msg.push(0x80)
      (1..padding).each do |b|
        msg.push(0x00)
      end
    elsif block_offset != 0
      raise ArgumentError.new("Message size is not a multiple of the block size")
    end

    blocks = msg.length / b_size
    cipher_text = []

    xor = xor_buffer(iv, msg[(0..(b_size - 1))])
    ct_block = @cipher.encrypt_block(xor, key)
    cipher_text.push(*ct_block)

    (1..(blocks - 1)).each do |b|
      pt_block = msg[((b_size * b)..(b_size * (b + 1) - 1))]
      xor = xor_buffer(ct_block, pt_block)
      ct_block = @cipher.encrypt_block(xor, key)
      cipher_text.push(*ct_block)
    end

    cipher_text
  end


  def decrypt(msg, key, iv, is_padded)

  end

end
