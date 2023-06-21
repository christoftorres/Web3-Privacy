<div align="center">
  <img src="architecture.png" width="300"/>
</div>

<h1 align="center">Is Your Wallet Snitching On You?</h1>

A framework to quantify Web3 privacy violations such as web3-based browser fingerprinting and wallet address leakage to third-parties by DApps and wallet extensions. Our paper can be found
[here](https://arxiv.org/pdf/2306.08170.pdf).

## Installation Instructions

### 1. Install MongoDB

##### MacOS

``` shell
brew tap mongodb/brew
brew install mongodb-community@4.4
```

For other operating systems follow the installation instructions on [mongodb.com](https://docs.mongodb.com/manual/installation/).

### 2. Install Python dependencies

``` shell
python3 -m pip install -r requirements.txt
```

### 3. Install Node.js

##### MacOS

``` shell
brew install node
```

For other operating systems follow the installation instructions on [nodejs.org](https://nodejs.org/en/download/package-manager/).

## Analysis

You can either run the data collection scripts or download our data from Google drive:

``` shell
cd data-collection
./download_and_import_data.sh

```

The bulk of the analysis was done in Jupyter notebooks, which can be opened by running:

``` shell
cd analysis
jupyter notebook
```
and selecting the notebook of choice.
