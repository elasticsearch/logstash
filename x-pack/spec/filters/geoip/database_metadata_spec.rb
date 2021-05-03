# # Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# # or more contributor license agreements. Licensed under the Elastic License;
# # you may not use this file except in compliance with the Elastic License.

require_relative 'test_helper'
require "filters/geoip/database_metadata"
require "filters/geoip/database_manager"
require "stud/temporary"

describe LogStash::Filters::Geoip do

  describe 'DatabaseMetadata', :aggregate_failures do
    let(:database_type) { "City" }
    let(:dbm) do
      dbm = LogStash::Filters::Geoip::DatabaseMetadata.new
      dbm.instance_variable_set(:@metadata_path, Stud::Temporary.file.path)
      dbm
    end
    let(:temp_metadata_path) { dbm.instance_variable_get(:@metadata_path) }
    let(:logger) { double("Logger") }

    before(:each) do
      LogStash::Filters::Geoip::DatabaseManager.prepare_cc_db
    end

    context "get all" do
      it "return multiple rows" do
        write_temp_metadata(temp_metadata_path, city2_metadata)

        expect(dbm.get_all.size).to eq(3)
      end
    end

    context "get metadata" do
      it "return metadata" do
        write_temp_metadata(temp_metadata_path, city2_metadata)

        city = dbm.get_metadata(database_type)
        expect(city.size).to eq(2)

        asn = dbm.get_metadata("ASN")
        expect(asn.size).to eq(1)
      end

      it "return empty array when file is missing" do
        metadata = dbm.get_metadata(database_type)
        expect(metadata.size).to eq(0)
      end

      it "return empty array when an empty file exist" do
        FileUtils.touch(temp_metadata_path)

        metadata = dbm.get_metadata(database_type)
        expect(metadata.size).to eq(0)
      end
    end

    context "save timestamp" do
      before do
        ::File.open(default_city_gz_path, "w") { |f| f.write "make a non empty file" }
      end

      after do
        delete_file(default_city_gz_path)
      end

      it "write the current time" do
        write_temp_metadata(temp_metadata_path)
        dbm.save_timestamp_database_path(database_type, default_city_db_path, true)

        expect(dbm.get_metadata(database_type).size).to eq(1)
        expect(dbm.get_all.size).to eq(2)

        metadata = dbm.get_metadata(database_type).last
        expect(metadata[LogStash::Filters::Geoip::DatabaseMetadata::Column::DATABASE_TYPE]).to eq("City")
        past = metadata[LogStash::Filters::Geoip::DatabaseMetadata::Column::UPDATE_AT]
        expect(Time.now.to_i - past.to_i).to be < 100
        expect(metadata[LogStash::Filters::Geoip::DatabaseMetadata::Column::GZ_MD5]).not_to be_empty
        expect(metadata[LogStash::Filters::Geoip::DatabaseMetadata::Column::GZ_MD5]).to eq(md5(default_city_gz_path))
        expect(metadata[LogStash::Filters::Geoip::DatabaseMetadata::Column::MD5]).to eq(default_city_db_md5)
        expect(metadata[LogStash::Filters::Geoip::DatabaseMetadata::Column::FILENAME]).to eq(default_city_db_name)
        expect(metadata[LogStash::Filters::Geoip::DatabaseMetadata::Column::IS_EULA]).to eq("true")
      end
    end

    context "database path" do
      it "return the default city database path" do
        write_temp_metadata(temp_metadata_path)

        expect(dbm.database_path(database_type)).to eq(default_city_db_path)
      end

      it "return the last database path with valid md5" do
        write_temp_metadata(temp_metadata_path, city2_metadata)

        expect(dbm.database_path(database_type)).to eq(default_city_db_path)
      end

      context "with ASN database type" do
        let(:database_type) { "ASN" }
        let(:dbm) do
          dbm = LogStash::Filters::Geoip::DatabaseMetadata.new
          dbm.instance_variable_set(:@metadata_path, Stud::Temporary.file.path)
          dbm
        end

        it "return the default asn database path" do
          write_temp_metadata(temp_metadata_path)

          expect(dbm.database_path(database_type)).to eq(default_asn_db_path)
        end
      end

      context "with invalid database type" do
        let(:database_type) { "???" }
        let(:dbm) do
          dbm = LogStash::Filters::Geoip::DatabaseMetadata.new
          dbm.instance_variable_set(:@metadata_path, Stud::Temporary.file.path)
          dbm
        end

        it "return nil if md5 not matched" do
          write_temp_metadata(temp_metadata_path)

          expect(dbm.database_path(database_type)).to be_nil
        end
      end
    end

    context "gz md5" do
      it "should give the last gz md5" do
        write_temp_metadata(temp_metadata_path, ["City","","SOME_GZ_MD5","SOME_MD5",second_city_db_name])
        expect(dbm.gz_md5(database_type)).to eq("SOME_GZ_MD5")
      end

      it "should give empty string if metadata is empty" do
        expect(dbm.gz_md5(database_type)).to eq("")
      end
    end

    context "updated at" do
      it "should give the last update timestamp" do
        write_temp_metadata(temp_metadata_path, ["City","1611690807","SOME_GZ_MD5","SOME_MD5",second_city_db_name])
        expect(dbm.updated_at(database_type)).to eq(1611690807)
      end

      it "should give 0 if metadata is empty" do
        expect(dbm.updated_at(database_type)).to eq(0)
      end
    end

    context "database filenames" do
      it "should give filename in .mmdb .tgz" do
        write_temp_metadata(temp_metadata_path)
        expect(dbm.database_filenames).to match_array([default_city_db_name, default_asn_db_name,
                                                       'GeoLite2-City.tgz', 'GeoLite2-ASN.tgz'])
      end
    end

    context "exist" do
      it "should be false because Stud create empty temp file" do
        expect(dbm.exist?).to be_falsey
      end

      it "should be true if temp file has content" do
        ::File.open(temp_metadata_path, "w") { |f| f.write("something") }

        expect(dbm.exist?).to be_truthy
      end
    end

    context "is eula" do
      it "should give boolean false if database is CC" do
        write_temp_metadata(temp_metadata_path)
        expect(dbm.is_eula(database_type)).to eq(false)
      end

      it "should give boolean true if database is EULA" do
        write_temp_metadata(temp_metadata_path, city2_metadata)
        expect(dbm.is_eula(database_type)).to eq(true)
      end
    end

    # context "update timestamp" do
    #   it "should update timestamp only" do
    #     write_temp_metadata(temp_metadata_path)
    #     original = dbm.get_all
    #     sleep(2)
    #
    #     dbm.update_timestamp
    #     updated = dbm.get_all
    #
    #     original.size.times do |i|
    #       expect(original[i][LogStash::Filters::Geoip::DatabaseMetadata::Column::DATABASE_TYPE]).
    #         to(eq(updated[i][LogStash::Filters::Geoip::DatabaseMetadata::Column::DATABASE_TYPE]))
    #       expect(original[i][LogStash::Filters::Geoip::DatabaseMetadata::Column::UPDATE_AT])
    #         .not_to(eq(updated[i][LogStash::Filters::Geoip::DatabaseMetadata::Column::UPDATE_AT]))
    #       expect(original[i][LogStash::Filters::Geoip::DatabaseMetadata::Column::GZ_MD5])
    #         .to(eq(updated[i][LogStash::Filters::Geoip::DatabaseMetadata::Column::GZ_MD5]))
    #       expect(original[i][LogStash::Filters::Geoip::DatabaseMetadata::Column::MD5])
    #         .to(eq(updated[i][LogStash::Filters::Geoip::DatabaseMetadata::Column::MD5]))
    #       expect(original[i][LogStash::Filters::Geoip::DatabaseMetadata::Column::FILENAME])
    #         .to(eq(updated[i][LogStash::Filters::Geoip::DatabaseMetadata::Column::FILENAME]))
    #       expect(original[i][LogStash::Filters::Geoip::DatabaseMetadata::Column::IS_EULA])
    #         .to(eq(updated[i][LogStash::Filters::Geoip::DatabaseMetadata::Column::IS_EULA]))
    #     end
    #   end
    # end
  end
end