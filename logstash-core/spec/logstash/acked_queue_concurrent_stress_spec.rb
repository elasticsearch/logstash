# Licensed to Elasticsearch B.V. under one or more contributor
# license agreements. See the NOTICE file distributed with
# this work for additional information regarding copyright
# ownership. Elasticsearch B.V. licenses this file to you under
# the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

require "logstash/instrument/namespaced_metric"

describe LogStash::WrappedAckedQueue, :stress_test => true do
  let(:path) { Stud::Temporary.directory }

  context "with multiple writers" do
    let(:items) { expected_count / writers }
    let(:page_capacity) { 1 << page_capacity_multiplier }
    let(:queue_capacity) { page_capacity * queue_capacity_multiplier }

    let(:output_strings) { [] }
    let(:reject_memo_keys) { [:reject_memo_keys, :path, :queue, :writer_threads, :collector, :metric, :reader_threads, :output_strings] }

    let(:queue) do
      described_class.new(path, page_capacity, 0, queue_checkpoint_acks, queue_checkpoint_writes, queue_checkpoint_interval, false, queue_capacity)
    end

    let(:writer_threads) do
      writer = queue.write_client
      writers.times.map do |i|
        Thread.new(i, items, writer) do |_i, _items, _writer|
          publisher(_items, _writer)
        end
      end
    end

    let(:writers_finished) { Concurrent::AtomicBoolean.new(false) }

    let(:reader_threads) do
      reader = queue.read_client
      reader.set_batch_dimensions(batch_size, batch_wait)
      reader.set_events_metric(metric.namespace([:stats, :events]))
      reader.set_pipeline_metric(metric.namespace([:stats, :pipelines, :main, :events]))

      readers.times.map do |i|
        Thread.new(i, reader, counts) do |_i, _reader, _counts|
          begin
            tally = 0
            while true
              batch = _reader.read_batch.to_java
              break if batch.filteredSize == 0 && writers_finished.value == true && queue.queue.is_fully_acked?
              sleep(rand * 0.01) if simulate_work
              tally += batch.filteredSize
              batch.close
            end
            _counts[_i] = tally
            # puts("reader #{_i}, tally=#{tally}, _counts=#{_counts.inspect}")
          rescue => e
            p :reader_error => e
          end
        end
      end
    end

    def publisher(items, writer)
      items.times.each do |i|
        event = LogStash::Event.new("sequence" => "#{i}".ljust(string_size))
        writer.push(event)
      end
    rescue => e
      p :publisher_error => e
    end

    let(:collector) { LogStash::Instrument::Collector.new }
    let(:metric) { LogStash::Instrument::Metric.new(collector) }

    shared_examples "a well behaved queue" do
      it "writes, reads, closes and reopens" do
        Thread.abort_on_exception = false

        # force lazy initialization to avoid concurrency issues within threads
        counts
        queue

        # Start the threads
        writer_threads
        reader_threads

        writer_threads.each(&:join)
        writers_finished.make_true

        reader_threads.each(&:join)

        enqueued = queue.queue.unread_count

        if enqueued != 0
          output_strings << "unread events in queue: #{enqueued}"
        end

        got = counts.reduce(&:+)

        if got != expected_count
          # puts("count=#{counts.inspect}")
          output_strings << "events read: #{got}"
        end

        sleep 0.1
        expect { queue.close }.not_to raise_error
        sleep 0.1
        files = Dir.glob(path + '/*').map {|f| f.sub("#{path}/", '')}
        if files.count != 2
          output_strings << "File count after close mismatch expected: 2 got: #{files.count}"
          output_strings.concat files
        end

        queue.close

        if output_strings.any?
          output_strings << __memoized.reject {|k, v| reject_memo_keys.include?(k)}.inspect
        end

        expect(output_strings).to eq([])
      end
    end

    let(:writers) { 3 }
    let(:readers) { 3 }
    let(:simulate_work) { true }
    let(:counts) { Concurrent::Array.new([0, 0, 0, 0, 0, 0, 0, 0]) }
    let(:page_capacity_multiplier) { 20 }
    let(:queue_capacity_multiplier) { 128 }
    let(:queue_checkpoint_acks) { 1024 }
    let(:queue_checkpoint_writes) { 1024 }
    let(:queue_checkpoint_interval) { 1000 }
    let(:batch_size) { 500 }
    let(:batch_wait) { 1000 }
    let(:expected_count) { 60000 }
    let(:string_size) { 256 }

    describe "with simulate_work ON" do
      let(:simulate_work) { true }

      context "> more writers than readers <" do
        let(:writers) { 4 }
        let(:readers) { 2 }
        it_behaves_like "a well behaved queue"
      end

      context "> less writers than readers <" do
        let(:writers) { 2 }
        let(:readers) { 4 }
        it_behaves_like "a well behaved queue"
      end

      context "> larger checkpoint acks <" do
        let(:queue_checkpoint_acks) { 3000 }
        it_behaves_like "a well behaved queue"
      end

      context "> smaller checkpoint acks <" do
        let(:queue_checkpoint_acks) { 500 }
        it_behaves_like "a well behaved queue"
      end

      context "> larger checkpoint writes <" do
        let(:queue_checkpoint_writes) { 3000 }
        it_behaves_like "a well behaved queue"
      end

      context "> smaller checkpoint writes <" do
        let(:queue_checkpoint_writes) { 500 }
        it_behaves_like "a well behaved queue"
      end

      context "> larger checkpoint interval <" do
        let(:queue_checkpoint_interval) { 3000 }
        it_behaves_like "a well behaved queue"
      end

      context "> smaller checkpoint interval <" do
        let(:queue_checkpoint_interval) { 500 }
        it_behaves_like "a well behaved queue"
      end

      context "> smaller batch wait <" do
        let(:batch_wait) { 125 }
        it_behaves_like "a well behaved queue"
      end

      context "> larger batch wait <" do
        let(:batch_wait) { 5000 }
        it_behaves_like "a well behaved queue"
      end

      context "> smaller event size <" do
        let(:string_size) { 8 }
        it_behaves_like "a well behaved queue"
      end

      context "> larger event size <" do
        let(:string_size) { 8192 }
        it_behaves_like "a well behaved queue"
      end

      context "> small queue size limit <" do
        let(:queue_capacity_multiplier) { 10 }
        it_behaves_like "a well behaved queue"
      end

      context "> very large queue size limit <" do
        let(:queue_capacity_multiplier) { 512 }
        it_behaves_like "a well behaved queue"
      end
    end

    describe "with simulate_work OFF" do
      let(:simulate_work) { false }

      context "> more writers than readers <" do
        let(:writers) { 4 }
        let(:readers) { 2 }
        it_behaves_like "a well behaved queue"
      end

      context "> less writers than readers <" do
        let(:writers) { 2 }
        let(:readers) { 4 }
        it_behaves_like "a well behaved queue"
      end

      context "> larger checkpoint acks <" do
        let(:queue_checkpoint_acks) { 3000 }
        it_behaves_like "a well behaved queue"
      end

      context "> smaller checkpoint acks <" do
        let(:queue_checkpoint_acks) { 500 }
        it_behaves_like "a well behaved queue"
      end

      context "> larger checkpoint writes <" do
        let(:queue_checkpoint_writes) { 3000 }
        it_behaves_like "a well behaved queue"
      end

      context "> smaller checkpoint writes <" do
        let(:queue_checkpoint_writes) { 500 }
        it_behaves_like "a well behaved queue"
      end

      context "> larger checkpoint interval <" do
        let(:queue_checkpoint_interval) { 3000 }
        it_behaves_like "a well behaved queue"
      end

      context "> smaller checkpoint interval <" do
        let(:queue_checkpoint_interval) { 500 }
        it_behaves_like "a well behaved queue"
      end

      context "> smaller batch wait <" do
        let(:batch_wait) { 125 }
        it_behaves_like "a well behaved queue"
      end

      context "> larger batch wait <" do
        let(:batch_wait) { 5000 }
        it_behaves_like "a well behaved queue"
      end

      context "> smaller event size <" do
        let(:string_size) { 8 }
        it_behaves_like "a well behaved queue"
      end

      context "> larger event size <" do
        let(:string_size) { 8192 }
        it_behaves_like "a well behaved queue"
      end

      context "> small queue size limit <" do
        let(:queue_capacity_multiplier) { 10 }
        it_behaves_like "a well behaved queue"
      end

      context "> very large queue size limit <" do
        let(:queue_capacity_multiplier) { 512 }
        it_behaves_like "a well behaved queue"
      end
    end
  end
end
