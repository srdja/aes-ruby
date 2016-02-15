
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
    cipher_text = []

    cipher_text.push(*@cipher.encrypt_block(msg[(0..(b_size - 1))], key))
    (1..(blocks - 1)).each do |b|
      b_range = ((b_size * b)..(b_size * (b + 1) - 1))
      cipher_text.push(*(@cipher.encrypt_block(msg[b_range], key)))
    end

    cipher_text
  end


  def decrypt(cipher_text, key)

  end

end
