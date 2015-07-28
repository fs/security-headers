module Headlines
  module SecurityHeaders
    describe XDownloadOptions do
      let(:name) { "x-download-options" }

      describe "#parse" do
        subject(:params) { described_class.new(name, value).params }

        context "header with noopen value" do
          let(:value) { "noopen" }

          its([:enabled]) { is_expected.to be_truthy }
        end

        context "header with wrong value" do
          let(:value) { "wrong value" }

          its([:enabled]) { is_expected.to be_falsey }
        end
      end

      describe "#score" do
        subject(:score) { described_class.new(name, value).score }

        context "for header with noopen value" do
          let(:value) { "noopen" }

          it { is_expected.to eq 1 }
        end

        context "for header with wrong value" do
          let(:value) { "wrong value" }

          it { is_expected.to eq 0 }
        end
      end
    end
  end
end
