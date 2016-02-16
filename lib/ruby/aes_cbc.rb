
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
    b_size = @cipher.block_size

    if msg.length % b_size != 0
      raise ArgumentError.new("Message size is not a multiple of the block size")
    end

    blocks = msg.length / b_size
    plain_text = []

    cipher_text_block = msg[(0..(b_size - 1))]
    transition_block = @cipher.decrypt_block(cipher_text_block, key)
    plain_text_block = xor_buffer(iv, transition_block)
    plain_text.push(*plain_text_block)

    (1..(blocks - 1)).each do |b|
      block = msg[(b_size * b)..(b_size * (b + 1) - 1)]
      transition_block = @cipher.decrypt_block(block, key)
      plain_text_block = xor_buffer(cipher_text_block, transition_block)
      cipher_text_block = block
      plain_text.push(*plain_text_block)
    end

    # Remove padding if the message was padded
    if is_padded
      p_len = 0
      (msg.length - 1).step(0, -1) do |b|
        byte = msg[i]
        p_len += 1
        if byte == 0x80
          break
        elsif byte != 0x00
          raise ArgumentError.new("No padding found")
        end
      end
      x.pop(p_len)
    end

    plain_text
  end

end
