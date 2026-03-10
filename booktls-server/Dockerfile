# Nginx build with OpenSSL container image.
# この Dockerfile は、Ubuntu 22.04 をベースにして、
# 1. OpenSSL をソースコードからビルドし、
# 2. その OpenSSL を使うように Nginx をソースコードからビルドし、
# 3. TLS/HTTPS の学習・検証用サーバ環境を作る
# ためのものです。
#
# 特に重要なのは、単に apt で nginx を入れるのではなく、
# `--with-openssl=...` を使って「指定した OpenSSL ソースと組み合わせて Nginx をビルド」している点です。
# これにより、OpenSSL の特定バージョンや特定ビルドオプションを使った TLS 挙動の検証ができます。

# ベースイメージとして Ubuntu 22.04 LTS を使います。
# 安定性が高く、パッケージも豊富なため、学習用・検証用の土台として扱いやすいです。
FROM ubuntu:22.04

# メンテナ情報です。
# 動作には直接影響しませんが、このイメージの作成者や管理者情報を残します。
LABEL maintainer="ITAKURA Hiroaki <piroakey@gmail.com>"

# OpenSSL のバージョンを環境変数として定義します。
# これにより、後続の download URL や展開先ディレクトリで同じ値を再利用できます。
#
# ここを変えると、以降の OpenSSL のダウンロードとビルド対象バージョンが変わります。
# TLS の挙動差分を学ぶときに便利です。
ENV OPENSSL_VERSION 3.0.12

# Nginx のバージョンを環境変数として定義します。
# OpenSSL と同様に、後続のダウンロード URL やソースディレクトリ名で使います。
ENV NGINX_VERSION 1.24.0

# apt 実行時の対話プロンプトを無効化します。
# Docker build 中に tzdata などが対話入力を求めるのを防ぎます。
ENV DEBIAN_FRONTEND=noninteractive

# ------------------------------------------------------------
# 学習用ユーザーの作成
# ------------------------------------------------------------

# openssl という一般ユーザーを作成します。
# -m によってホームディレクトリも自動で作られます。
#
# gpasswd -a openssl sudo
# → openssl ユーザーを sudo グループに追加します。
#
# echo "openssl:openssl" | chpasswd
# → パスワードを設定します。
#
# 注意:
# このような固定パスワードは学習用途では便利ですが、
# 実運用では危険なので避けるべきです。
RUN useradd -m openssl \
 && gpasswd -a openssl sudo \
 && echo "openssl:openssl" | chpasswd

# ------------------------------------------------------------
# root 権限でビルド作業を行う
# ------------------------------------------------------------

# 以降のインストールやビルドは root 権限で行います。
USER root

# 作業ディレクトリを /root に設定します。
# ソースコードのダウンロード・展開・ビルドをここで行います。
WORKDIR /root

# ------------------------------------------------------------
# www-data ユーザーの調整
# ------------------------------------------------------------

# Ubuntu には通常 www-data ユーザーが存在します。
# ここでは、そのホームディレクトリとシェルを変更しています。
#
# --home /etc/nginx
# → ホームディレクトリを /etc/nginx に変更
#
# --shell /sbin/nologin
# → ログインシェルを無効化
#
# つまり、「Webサーバ実行専用ユーザー」としての性格を強めています。
# Nginx プロセスは通常 root ではなく www-data などの低権限ユーザーで動くため、
# 最小権限原則に沿った設定です。
RUN usermod www-data --home /etc/nginx --shell /sbin/nologin

# ------------------------------------------------------------
# 依存パッケージのインストール
# ------------------------------------------------------------

# apt-get update
# → パッケージ一覧更新
#
# --no-install-recommends
# → 推奨パッケージを入れず、イメージ肥大化を防ぐ
#
# 主な依存関係:
#
# ca-certificates
#   HTTPS 通信や証明書検証の基盤
#
# curl
#   ソースコード取得用
#
# gcc / make / perl
#   OpenSSL / Nginx のビルドに必要
#
# libpcre3 / libpcre3-dev
#   Nginx の rewrite/location マッチング等で用いる PCRE に必要
#
# zlib1g-dev
#   gzip 関連モジュールや圧縮機能のために必要
#
# libxslt-dev / libgd-dev
#   nginx の動的モジュール
#   `http_xslt_module` や `http_image_filter_module` のビルドに必要
#
# sudo / vim / dnsutils / gdb
#   学習・デバッグ・運用確認用
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    gcc \
    libpcre3 \
    libpcre3-dev \
    make \
    perl \
    sudo \
    vim \
    zlib1g-dev \
    libxslt-dev \
    libgd-dev \
    tzdata \
    dnsutils \
    gdb \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/*

# apt キャッシュ削除により、イメージサイズを抑えています。

# ------------------------------------------------------------
# sudo 設定
# ------------------------------------------------------------

# sudo グループのユーザーに対して、パスワードなし sudo を許可します。
# 学習用途では便利ですが、本番では強すぎる設定になりやすいです。
RUN echo '%sudo ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers

# ------------------------------------------------------------
# OpenSSL 単体ビルド
# ------------------------------------------------------------

# まず OpenSSL を単体でビルドして /opt/openssl にインストールします。
# ここでの目的は、
# - OpenSSL コマンド群をコンテナ内で単体利用できるようにする
# - OpenSSL ライブラリを確認・実験しやすくする
# ことです。
#
# 後段では Nginx 用にも OpenSSL ソースを別途展開して使っているため、
# 「単体利用の OpenSSL」と「Nginx 組み込み用の OpenSSL ソース」を
# 分けている構成になっています。
RUN curl -sSLO https://www.openssl.org/source/openssl-$OPENSSL_VERSION.tar.gz \

# ダウンロードした tar.gz を展開します。
 && tar xvf openssl-$OPENSSL_VERSION.tar.gz \

# 圧縮ファイル本体は不要になるので削除します。
 && rm -v openssl-$OPENSSL_VERSION.tar.gz \

# 展開した OpenSSL ソースディレクトリに移動します。
 && cd "/root/openssl-$OPENSSL_VERSION/" \

# OpenSSL のビルド設定を行います。
#
# --prefix=/opt/openssl
# → インストール先を /opt/openssl に指定
#
# shared
# → 共有ライブラリ (.so) を生成
#   動的リンクで使いやすくなります
#
# enable-ec_nistp_64_gcc_128
# → 64bit 環境での特定の楕円曲線演算最適化
#   TLS で ECC を使う際の性能改善が期待されます
 && ./config --prefix=/opt/openssl \
        shared \
        enable-ec_nistp_64_gcc_128 \

# 依存関係を生成します。
 && make depend \

# 並列ビルドを実行します。
# 本来ここでは `$(nproc)` のようなコマンド置換がよく使われますが、
# 現在の `${nproc}` だと環境変数 nproc が定義されていない限り空になりうるため、
# ビルド環境によっては期待通りにならない可能性があります。
#
# 補完・改善するなら本来は以下の方が安全です。
# make -j "$(nproc)"
#
# ただし、ここでは元コードの意図を尊重して詳細コメントを付けています。
 && make -j ${nproc} \

# ソフトウェア本体をインストールします。
# `install_sw` は主にライブラリ・ヘッダ・バイナリを入れるターゲットで、
# man ページ等は省かれます。
 && make install_sw \

# ソースディレクトリを削除します。
# イメージサイズ削減のためです。
 && rm -R "/root/openssl-$OPENSSL_VERSION/"

# ------------------------------------------------------------
# Nginx + OpenSSL ソースの取得とビルド
# ------------------------------------------------------------

# ここでは Nginx と、Nginx 組み込み用 OpenSSL ソースを同時に取得します。
#
# なぜ OpenSSL をもう一度ダウンロードするのか:
# `--with-openssl=...` は「OpenSSL を外部ライブラリとしてリンクする」だけではなく、
# Nginx のビルド過程の中で OpenSSL ソースを使って組み込むためです。
#
# そのため、/opt/openssl にインストール済みの OpenSSL とは別に、
# Nginx ビルド用ソース一式が必要になります。
RUN curl -sSLO https://www.openssl.org/source/openssl-$OPENSSL_VERSION.tar.gz \
 && curl -sSLO https://nginx.org/download/nginx-$NGINX_VERSION.tar.gz \

# OpenSSL ソース展開
 && tar xzvf openssl-$OPENSSL_VERSION.tar.gz \
 && rm -v openssl-$OPENSSL_VERSION.tar.gz \

# Nginx ソース展開
 && tar xzvf nginx-$NGINX_VERSION.tar.gz \
 && rm -v nginx-$NGINX_VERSION.tar.gz \

# Nginx ソースディレクトリへ移動
 && cd "/root/nginx-$NGINX_VERSION/" \

# ------------------------------------------------------------
# Nginx configure
# ------------------------------------------------------------

# Nginx を細かいオプション付きで configure します。
#
# --with-cc-opt
# → C コンパイラ向けの安全化・最適化オプション
#
#   -O2
#     一般的な最適化
#
#   -fstack-protector-strong
#     スタック破壊検知を強化
#
#   -Wformat -Werror=format-security
#     format string 問題を警告・エラー化
#
#   -fPIC
#     位置独立コード生成
#
#   -Wdate-time
#     __DATE__ / __TIME__ 等の利用に警告
#
#   -D_FORTIFY_SOURCE=2
#     バッファ操作の保護を強化
#
# --with-ld-opt
# → リンカ向けの安全化オプション
#
#   -Wl,-z,relro
#     GOT/PLT 領域の一部を保護
#
#   -Wl,-z,now
#     遅延解決を避け、起動時に解決
#     RELRO 強化と組み合わせて使われることが多い
#
# --prefix=/etc/nginx
# → Nginx の設定ファイル類やルートを /etc/nginx に置く
#
# --sbin-path=/usr/sbin/nginx
# → nginx 実行バイナリの配置場所
#
# 各種 *-path
# → ログ・PID・一時ファイル格納先を明示
#
# --with-compat
# → 動的モジュール互換性
#
# --with-pcre-jit
# → PCRE の JIT 最適化
#
# --with-http_ssl_module
# → HTTPS/TLS を扱う上で必須のモジュール
#
# --with-http_v2_module
# → HTTP/2 対応
#
# --with-stream=dynamic / --with-stream_ssl_module
# → TCP/UDP レベルの stream 処理や TLS 対応
#
# --with-mail=dynamic / --with-mail_ssl_module
# → mail プロトコル用の SSL サポート
#
# --with-openssl="$HOME/openssl-$OPENSSL_VERSION"
# → Nginx ビルド時に使用する OpenSSL ソースの場所
#
# --with-openssl-opt="enable-ec_nistp_64_gcc_128"
# → OpenSSL 側にも同じ最適化オプションを付与
#
# これにより、
# 「指定した OpenSSL バージョンとオプションを用いた Nginx」
# を再現可能な形でビルドできます。
 && ./configure --with-cc-opt='-O2 -fstack-protector-strong -Wformat -Werror=format-security -fPIC -Wdate-time -D_FORTIFY_SOURCE=2' \
        --with-ld-opt='-Wl,-Bsymbolic-functions -Wl,-z,relro -Wl,-z,now -fPIC' \
        --prefix=/etc/nginx \
        --sbin-path=/usr/sbin/nginx \
        --conf-path=/etc/nginx/nginx.conf \
        --http-log-path=/var/log/nginx/access.log \
        --error-log-path=/var/log/nginx/error.log \
        --lock-path=/var/lock/nginx.lock \
        --pid-path=/run/nginx.pid \
        --modules-path=/usr/lib/nginx/modules \
        --http-client-body-temp-path=/var/cache/nginx/client_temp \
        --http-fastcgi-temp-path=/var/cache/nginx/fastcgi_temp \
        --http-proxy-temp-path=/var/cache/nginx/proxy_temp \
        --http-scgi-temp-path=/var/cache/nginx/scgi_temp \
        --http-uwsgi-temp-path=/var/cache/nginx/uwsgi_temp \
        --with-compat \
        --with-pcre-jit \
        --with-http_ssl_module \
        --with-http_stub_status_module \
        --with-http_realip_module \
        --with-http_auth_request_module \
        --with-http_v2_module \
        --with-http_dav_module \
        --with-http_slice_module \
        --with-threads \
        --with-http_addition_module \
        --with-http_gunzip_module \
        --with-http_gzip_static_module \
        --with-http_image_filter_module=dynamic \
        --with-http_sub_module \
        --with-http_xslt_module=dynamic \
        --with-stream=dynamic \
        --with-stream_ssl_module \
        --with-mail=dynamic \
        --with-mail_ssl_module \
        --with-openssl="$HOME/openssl-$OPENSSL_VERSION" \
        --with-openssl-opt="enable-ec_nistp_64_gcc_128" \

# Nginx をビルドします。
# ここも `${nproc}` より `$(nproc)` の方が一般には確実です。
 && make -j ${nproc} \

# Nginx をインストールします。
# configure で指定した各種パスに従って配置されます。
 && make install \

# ソースコードを削除してイメージサイズを削減します。
 && rm -R "/root/nginx-$NGINX_VERSION" \
 && rm -R "/root/openssl-$OPENSSL_VERSION/"

# ------------------------------------------------------------
# エントリスクリプト / エディタ設定
# ------------------------------------------------------------

# 初期化スクリプトをコピーします。
# コンテナ起動時やシェル開始時に環境変数設定などを行う想定です。
COPY init.sh /home/openssl/init.sh

# 所有権を openssl ユーザーへ変更します。
RUN chown openssl:openssl /home/openssl/init.sh

# vim の設定ファイルをコピーします。
COPY .vimrc /home/openssl/.vimrc

# 所有権を openssl ユーザーへ変更します。
RUN chown openssl:openssl /home/openssl/.vimrc

# ------------------------------------------------------------
# 共有ディレクトリ
# ------------------------------------------------------------

# ホストや別コンテナと共有する前提の /share を作成します。
# docker compose の volume マウントと組み合わせて使う想定です。
RUN mkdir -p /share

# openssl ユーザーが扱えるように所有権を変更します。
RUN chown -R openssl:openssl /share

# ------------------------------------------------------------
# Nginx 設定・証明書の配置
# ------------------------------------------------------------

# Nginx のメイン設定ファイルをコピーします。
# TLS バージョン制御、listen ポート、証明書パス、cipher suites などを
# ここで定義している想定です。
COPY conf/nginx.conf /etc/nginx/nginx.conf

# サーバ証明書を配置します。
# HTTPS サーバとして名乗る際に、クライアントへ提示する公開証明書です。
COPY certs/server.crt /etc/nginx/certs/server.crt

# サーバ秘密鍵を配置します。
# TLS ハンドシェイクでサーバ自身の正当性を示すために必要です。
#
# 重要:
# 秘密鍵は絶対に漏えいさせてはいけません。
# 学習環境であっても、Git 管理やログ出力には注意が必要です。
COPY certs/server.key /etc/nginx/certs/server.key

# ------------------------------------------------------------
# Nginx 実行に必要な権限・ディレクトリ準備
# ------------------------------------------------------------

# /etc/nginx 配下、ログディレクトリ、キャッシュディレクトリ、PID ファイルの
# 所有者を www-data に調整します。
#
# Nginx は通常 root が起動しても worker は低権限ユーザーで動くため、
# 実行時に必要な書き込み権限を整えておく必要があります。
RUN chown -R www-data:www-data /etc/nginx \
 && chown -R www-data:www-data /var/log/nginx \
 && mkdir -p /var/cache/nginx/ \
 && chown -R www-data:www-data /var/cache/nginx/ \
 && touch /var/run/nginx.pid \
 && chown -R www-data:www-data /var/run/nginx.pid

# ------------------------------------------------------------
# ビルド結果の確認
# ------------------------------------------------------------

# nginx -V
# → ビルドオプションやリンク情報を表示します。
#
# この出力は非常に重要です。
# 「本当に http_ssl_module が入っているか」
# 「どの OpenSSL を使っているか」
# 「どんな configure オプションで作られたか」
# を確認できます。
#
# SSL/TLS 学習では、まず `nginx -V` を見てビルド構成を把握する癖が重要です。
RUN nginx -V

# ------------------------------------------------------------
# 一般ユーザー環境の準備
# ------------------------------------------------------------

# いったん openssl ユーザーへ切り替えます。
# これは bashrc への初期化設定追加のためです。
USER openssl

# ホームディレクトリへ移動します。
WORKDIR /home/openssl

# bash 起動時に init.sh を読み込むようにします。
# PATH の追加や alias 設定などを想定できます。
RUN echo '. /home/openssl/init.sh' >> ~/.bashrc

# ------------------------------------------------------------
# 実行ユーザーを Web サーバ用に切り替える
# ------------------------------------------------------------

# 最終的に Nginx 自体は www-data ユーザーで起動します。
# これはセキュリティ的に好ましい構成です。
USER www-data

# 作業ディレクトリを Nginx 設定ディレクトリにします。
WORKDIR /etc/nginx

# ------------------------------------------------------------
# ポート公開
# ------------------------------------------------------------

# 443
# → 元々の HTTPS 用ポート
#
# 10080
# → HTTP 用の検証ポート
#
# 10443
# → HTTPS 用の検証ポート
#    たとえば TLS 1.2 / TLS 1.3 比較用
#
# 10444
# → 別条件の HTTPS ポート
#    たとえば「最小曲線だけ許可」などの比較実験用
#
# 学習環境では、複数ポートで TLS 設定を変えて比較するのはとても有効です。
EXPOSE 443 10080 10443 10444

# ------------------------------------------------------------
# コンテナ起動時のメインプロセス
# ------------------------------------------------------------

# nginx をフォアグラウンドで起動します。
#
# -g "daemon off;"
# → デーモン化せず前面で動かす
#
# Docker コンテナでは、PID 1 として前面実行するのが基本です。
# これによりコンテナの生存監視やログ取得がしやすくなります。
CMD ["nginx", "-g", "daemon off;"]