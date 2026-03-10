# OpenSSL container image.
# この Dockerfile は、OpenSSL をソースコードからビルドした環境を作るためのものです。
# Ubuntu ベースのコンテナを用意し、その中に OpenSSL をコンパイルして配置し、
# TLS の学習や実験を行える開発環境を構築します。

# ベースとなるコンテナイメージ。
# Ubuntu 22.04 LTS を使用しています。
# セキュリティ実験やネットワークツールの利用に向いた安定したディストリビューションです。
FROM ubuntu:22.04

# Dockerイメージのメンテナ情報です。
# 実際の動作には影響しませんが、誰が管理しているイメージかを示します。
LABEL maintainer="ITAKURA Hiroaki <piroakey@gmail.com>"

# OpenSSL のバージョンを環境変数として定義します。
# こうしておくことで、Dockerfile 内の複数箇所で同じ値を使い回せます。
# バージョン変更時もここだけ修正すればよくなります。
# 例:
# https://www.openssl.org/source/
ENV OPENSSL_VERSION 3.0.12

# apt 実行時の対話プロンプトを無効化します。
# Docker ビルド中に tzdata などのパッケージが
# 「タイムゾーン選択」などを聞いてくるのを防ぎます。
ENV DEBIAN_FRONTEND=noninteractive

# ------------------------------------------------------------
# ユーザー作成
# ------------------------------------------------------------

# openssl というユーザーを作成します。
# -m はホームディレクトリを作成するオプションです。
#
# gpasswd -a openssl sudo
# → sudo グループへ追加します。
#
# echo "openssl:openssl" | chpasswd
# → openssl ユーザーのパスワードを設定します。
#
# 学習用途のため簡易的なパスワードになっていますが、
# 実運用ではこのような固定パスワードは避けるべきです。
RUN useradd -m openssl \
 && gpasswd -a openssl sudo \
 && echo "openssl:openssl" | chpasswd

# ------------------------------------------------------------
# root 権限でのビルド設定
# ------------------------------------------------------------

# 以降の処理を root ユーザーで実行します。
# ソフトウェアのインストールやシステム設定変更が可能になります。
USER root

# 作業ディレクトリを /root に設定します。
# ここに OpenSSL ソースコードをダウンロードしてビルドします。
WORKDIR /root

# ------------------------------------------------------------
# 依存パッケージのインストール
# ------------------------------------------------------------

# apt-get update
# → パッケージインデックスを更新
#
# --no-install-recommends
# → 必須パッケージのみインストールし、余計な依存を減らします。
#
# インストールしている主なツール
#
# ca-certificates
#   TLS通信の証明書検証用
#
# curl
#   ソースコードのダウンロード
#
# gcc / make / perl
#   OpenSSL のビルドに必要
#
# iproute2 / net-tools / iputils-ping
#   ネットワーク検証用ツール
#
# dnsutils
#   DNS確認 (dig / nslookup)
#
# gdb
#   デバッグ
#
# vim
#   コンテナ内編集
#
# zlib1g-dev
#   OpenSSL圧縮機能の依存
#
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    gcc \
    iproute2 \
    iputils-ping \
    net-tools \
    make \
    perl \
    sudo \
    vim \
    zlib1g-dev \
    tzdata \
    dnsutils \
    gdb \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/*

# apt キャッシュを削除しています。
# これにより Docker イメージサイズを小さくできます。

# ------------------------------------------------------------
# sudo 設定
# ------------------------------------------------------------

# sudo グループに属するユーザーが
# パスワード無しで sudo を実行できるように設定します。
#
# %sudo
# → sudoグループ
#
# NOPASSWD
# → パスワード無し
RUN echo '%sudo ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers

# ------------------------------------------------------------
# OpenSSL ソースコード取得
# ------------------------------------------------------------

# curl -sSLO
# s: silent
# S: エラー表示
# L: リダイレクト追跡
# O: 元ファイル名で保存
RUN curl -sSLO https://www.openssl.org/source/openssl-$OPENSSL_VERSION.tar.gz \

# tar xvf
# → ソースコード展開
 && tar xvf openssl-$OPENSSL_VERSION.tar.gz \

# ダウンロードした tar を削除
 && rm -v openssl-$OPENSSL_VERSION.tar.gz \

# ソースディレクトリへ移動
 && cd "/root/openssl-$OPENSSL_VERSION/" \

# ------------------------------------------------------------
# OpenSSL ビルド設定
# ------------------------------------------------------------

# ./config
#
# --prefix=/opt/openssl
# → OpenSSL を /opt/openssl にインストール
#
# shared
# → 共有ライブラリをビルド
#
# enable-ec_nistp_64_gcc_128
# → ECC の高速化オプション
#   64bit CPU + GCC 最適化
#
 && ./config --prefix=/opt/openssl \
        shared \
        enable-ec_nistp_64_gcc_128 \

# 依存関係生成
 && make depend \

# 並列ビルド
#
# ${nproc}
# → CPUコア数
#
# 例:
# make -j 8
#
# Docker環境ではビルド時間短縮になります
 && make -j ${nproc} \

# ソフトウェアインストール
#
# install_sw
# → ソフトウェア部分のみ
# manやdocsを除く
 && make install_sw \

# ビルドディレクトリ削除
# イメージサイズ削減
 && rm -R "/root/openssl-$OPENSSL_VERSION/"

# ------------------------------------------------------------
# CA証明書配置
# ------------------------------------------------------------

# CA証明書をコンテナへコピー
# TLS検証実験などで使用します
COPY ca.pem /home/openssl/ca.pem

# 所有者変更
# opensslユーザーが扱えるようにする
RUN chown openssl:openssl /home/openssl/ca.pem

# ------------------------------------------------------------
# 初期化スクリプト
# ------------------------------------------------------------

# コンテナ起動時の初期処理スクリプト
COPY init.sh /home/openssl/init.sh

# 所有権変更
RUN chown openssl:openssl /home/openssl/init.sh

# ------------------------------------------------------------
# vim設定
# ------------------------------------------------------------

# vim設定ファイルをコピー
COPY .vimrc /home/openssl/.vimrc

RUN chown openssl:openssl /home/openssl/.vimrc

# ------------------------------------------------------------
# 共有ディレクトリ
# ------------------------------------------------------------

# /share を作成
# docker compose でホストと共有する想定
RUN mkdir -p /share

# 所有権変更
RUN chown -R openssl:openssl /share

# ------------------------------------------------------------
# 実行ユーザー変更
# ------------------------------------------------------------

# rootではなく openssl ユーザーで動かします。
# セキュリティ上の基本原則
# 「least privilege (最小権限)」
USER openssl

# 作業ディレクトリ
WORKDIR /home/openssl

# ------------------------------------------------------------
# bash 起動時設定
# ------------------------------------------------------------

# bash起動時に init.sh を読み込みます。
# TLS実験用の環境変数やパス設定を行う想定です。
RUN echo '. /home/openssl/init.sh' >> ~/.bashrc

# ------------------------------------------------------------
# コンテナ起動コマンド
# ------------------------------------------------------------

# ENTRYPOINT
#
# コンテナ起動時に必ず実行されるコマンド
#
# init.sh
# → 初期化処理
#
# /usr/bin/bash
# → 対話シェル
#
# つまり
#
# 1. init.sh 実行
# 2. bash 起動
#
ENTRYPOINT ["/home/openssl/init.sh", "/usr/bin/bash"]