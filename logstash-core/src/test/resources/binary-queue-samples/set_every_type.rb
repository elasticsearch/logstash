def filter(event)
  event.set('bigint', 99999999999999999999999999999999999)
  event.set('int_max', 2147483647)
  event.set('int_min', -2147483648)
  event.set('long_max', 9223372036854775807)
  event.set('long_min', -9223372036854775808)
  event.set('string', 'I am a string!')
  event.set('utf8_string', 'multibyte-chars-follow-十進数ウェブの国際化慶-and-here-they-end')
  event.set('boolean', false)
  event.set('timestamp', ::LogStash::Timestamp.new("2018-05-18T17:27:02.397Z"))

  event.set('nested_map', {
      'string' => "I am a string!"
  })

  event.set('mixed_array', ["a", 1, "b", ::LogStash::Timestamp.new, true]);

  event.set('complex', [
      {"a" => 1},
      {"b" => ["a string", 2]},
      {"c" =>  [
          {"x" => "y", "z" => true}
        ] }
  ])

  return [event]
end