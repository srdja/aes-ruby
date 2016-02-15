
# Electronic codeblock mode
#
# Each block of the message is encrypted independantly of other blocks.
class AES_ECB


  def initialize(cipher)
    @cipher = cipher
  end


  def encrypt(msg, key, padding)
    b_size = @cipher.block_size
    block_offset = msg.length % b_size

    # Add padding
    if padding
      padding = (block_offset == 0) ? 15 : (block_offset - 1)

      msg.push(0x80)
      (1..padding).each do |b|
        msg.push(0x00)
      end
    elsif block_offset != 0
      raise ArgumentError.new("Message size is not a multiple of the block size")
    end

    blocks = msg.length / b_size

    cipher_text = @cipher.encrypt_block(msg[(0..(b_size - 1))], key)

    (1..(blocks - 1)).each do |b|
      b_range = ((b_size * b)..(b_size * (b + 1) - 1))
      cipher_text.push(*(@cipher.encrypt_block(msg[b_range], key)))
    end

    cipher_text
  end


  def decrypt(msg, key, padded)
    b_size = @cipher.block_size

    if msg.length % b_size != 0
      raise ArgumentError.new("Message size is not a multiple of the block size")
    end

    blocks = msg.length / b_size

    plain_text = @cipher.decrypt_block(msg[(0..(b_size - 1))], key)
    (1..(blocks - 1)).each do |b|
      b_range = ((b_size * b)..(b_size * (b + 1) - 1))
      plain_text.push(*(@cipher.decrypt_block(msg[b_range], key)))
    end

    # Remove padding if the message was padded
    if padded
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
