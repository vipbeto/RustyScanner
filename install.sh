#!/bin/sh

# Atualizando pacotes
echo "Instalando pacotes necessários..."
pkg install rust git pkg-config -y

# Verificando se o diretório já existe e removendo se necessário
if [ -d "$HOME/RustyScanner" ]; then
  echo "Removendo diretório existente do RustyScanner..."
  rm -rf ~/RustyScanner
fi

# Clonando o repositório
echo "Clonando o repositório do RustyScanner..."
git clone https://github.com/adfastltda/RustyScanner.git ~/RustyScanner

# Verificando se o clone foi bem-sucedido
if [ ! -d "$HOME/RustyScanner" ]; then
  echo "Falha ao clonar o repositório!"
  exit 1
fi

# Construindo o projeto
cd ~/RustyScanner/Scan/
echo "Compilando o RustyScanner..."
cargo build --release

# Movendo o binário para o diretório $PREFIX/bin
echo "Movendo o binário para $PREFIX/bin/scan..."
cp target/release/scanner $PREFIX/bin/scan

# Limpando o diretório do repositório clonado
echo "Removendo diretório do repositório clonado..."
rm -rf ~/RustyScanner

# Testando a instalação
echo "Instalação concluída! Testando o comando 'scan'..."
scan -h
