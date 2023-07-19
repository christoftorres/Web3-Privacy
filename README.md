<div align="center">
  <img src="architecture.png" width="800"/>
</div>

<h1 align="center">Is Your Wallet Snitching On You?</h1>

A framework to quantify Web3 privacy violations such as Web3-based browser fingerprinting and wallet address leakage to third-parties by DApps and wallet extensions. Our paper can be found
[here](https://arxiv.org/pdf/2306.08170.pdf).

## Installation Instructions

### 1. Install MongoDB

##### MacOS

``` shell
brew tap mongodb/brew
brew update
brew install mongodb-community@6.0
```

##### Linux

``` shell
sudo apt-get install gnupg curl
curl -fsSL https://pgp.mongodb.com/server-6.0.asc | sudo gpg -o /usr/share/keyrings/mongodb-server-6.0.gpg --dearmor
echo "deb [ arch=amd64,arm64 signed-by=/usr/share/keyrings/mongodb-server-6.0.gpg ] https://repo.mongodb.org/apt/ubuntu jammy/mongodb-org/6.0 multiverse" | tee /etc/apt/sources.list.d/mongodb-org-6.0.list
sudo apt-get update
sudo apt-get install -y mongodb-org
```

For other operating systems follow the installation instructions on [mongodb.com](https://docs.mongodb.com/manual/installation/).

### 2. Install Python and its dependencies

##### MacOS

``` shell
python3 -m pip install -r requirements.txt
```

##### Linux

``` shell
sudo apt-get update -q
sudo apt-get install -y software-properties-common python3-distutils python3-pip python3-apt python3-dev
python3 -m pip install -r requirements.txt
```

### 3. Install Node.js and its dependencies

##### MacOS

``` shell
brew install node
cd framework/tracker-radar-collector
npm install
cd framework/request-interceptor
npm install
```

##### Linux

``` shell
curl -sL https://deb.nodesource.com/setup_18.x | bash -
apt-get update -q && apt-get install -y nodejs
cd framework/tracker-radar-collector
npm install
cd framework/request-interceptor
npm install
```

For other operating systems follow the installation instructions on [nodejs.org](https://nodejs.org/en/download/package-manager/).

## Download datasets and results

``` shell
wget https://zenodo.org/record/8071006/files/browser-fingerprinting-datasets.zip
unzip browser-fingerprinting-datasets.zip
mv datasets browser-fingerprinting/
rm browser-fingerprinting-datasets.zip
```

``` shell
wget https://zenodo.org/record/8071006/files/browser-fingerprinting-results.zip
unzip browser-fingerprinting-results.zip
mv results browser-fingerprinting/
rm browser-fingerprinting-results.zip
```

``` shell
wget https://zenodo.org/record/8071006/files/wallet-address-leakage-datasets.zip
unzip wallet-address-leakage-datasets.zip
mv datasets wallet-address-leakage/
rm wallet-address-leakage-datasets.zip
```

``` shell
wget https://zenodo.org/record/8071006/files/wallet-address-leakage-results.zip
unzip wallet-address-leakage-results.zip
mv results wallet-address-leakage/
rm wallet-address-leakage-results.zip
```

## Running Instructions

### Detect Web3-based browser fingerprinting

To detect for example if ```nytimes.com``` tries to access wallet information such as ```window.ethereum```, run the following commands:

``` shell
cd framework/tracker-radar-collector
npm run crawl -- -u "https://www.nytimes.com" -o ./data/ -f -v -d "requests,targets,apis,screenshots"
cat data/www.nytimes.com_89db.json | grep ethereum -C 10
```

The terminal should display ```window.ethereum``` along with other JavaScript properties.

### Analyze Web3-based browser fingerprinting

To analyze Web3-based browser fingerprinting and reproduce the results in our paper, run the following commands:

``` shell
cd browser-fingerprinting/results
mkdir db
mongod --dbpath db
mongoimport --uri="mongodb://localhost:27017/web3_privacy" --collection fingerprinting_results --type json --file fingerprinting_results.json
```

``` shell
cd browser-fingerprinting/analysis
python3 analyze_detected_fingerprinting.py
```

### Detect wallet address leakage

To detect for example if ```notional.finance``` is leaking your wallet address to a third-party, run the following commands:

``` shell
cd framework/request-interceptor
node run --interactive -u https://notional.finance/portfolio --debug verbose -w metamask-chrome-10.22.2 -t 30
cat notional.finance.json | grep 7e4abd63a7c8314cc28d388303472353d884f292
```

The terminal should display several entries which highlight that the wallet address is being leaked by the DApp to third-parties.

### Analyze wallet address leakage

To analyze wallet address leakage and reproduce the results in our paper, run the following commands:

``` shell
cd wallet-address-leakage/analysis
python3 find-leaks-and-scripts-winter-et-al.py ../results/whats_in_your_wallet/crawl ../datasets/whats_in_your_wallet
python3 find-leaks-and-scripts-dapps.py
python3 find-leaks-and-scripts-wallet-extensions.py
```

