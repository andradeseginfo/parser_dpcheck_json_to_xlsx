import sys
import os
import pandas as pd
import json
from datetime import date

def processar_json(nome_arquivo):
    # Carregar o JSON
    with open(nome_arquivo) as f:
        data = json.load(f)

    # Verificar se o campo 'dependencies' está vazio
    if not data.get('dependencies'):
        print("[INFO] O SCAN SCA NÃO DETECTOU VULNERABILIDADES.")
        return

    # Extrair informações relevantes do JSON
    dependencies = data.get('dependencies')

    # Criar um DataFrame do pandas incluindo apenas as colunas desejadas
    df = pd.DataFrame(dependencies, columns=['isVirtual', 'fileName', 'filePath', 'vulnerabilities'])

    # Filtrar apenas as linhas em que 'isVirtual' é verdadeiro (True)
    df = df[df['isVirtual'] == True]

    # Se 'vulnerabilities' for uma lista de dicionários, expandir em colunas separadas
    if 'vulnerabilities' in df.columns:
        # Extrair informações-chave da lista de dicionários em 'vulnerabilities'
        df['CWE'] = df['vulnerabilities'].apply(lambda x: x[0]['cwes'] if isinstance(x, list) and x else None)
        df['References'] = df['vulnerabilities'].apply(lambda x: x[0]['references'] if isinstance(x, list) and x else None)
        df['Severity'] = df['vulnerabilities'].apply(lambda x: x[0]['severity'].upper() if isinstance(x, list) and x else None)
        df['Description'] = df['vulnerabilities'].apply(lambda x: x[0]['description'].replace('\n', ' ') if isinstance(x, list) and x else None)
        df['CVE/GHSA'] = df['vulnerabilities'].apply(lambda x: x[0]['name'].upper() if isinstance(x, list) and x else None)

        # Remover a coluna original 'vulnerabilities'
        df = df.drop('vulnerabilities', axis=1)

    # Remover a coluna 'isVirtual'
    df = df.drop('isVirtual', axis=1)

    # Adicionar coluna com a data atual
    df['Date'] = date.today()

    # Adicionar coluna com o nome do arquivo JSON
    nome_arquivo_sem_extensao = os.path.splitext(os.path.basename(nome_arquivo))[0]
    df['Repository'] = nome_arquivo_sem_extensao

    # Adicionar coluna 'Source' com o valor padrão 'SCA'
    df['Source'] = 'SCA'
    df['URL'] = ''
    df['Solution'] = ''
    df['Lines'] = ''
    df['Code']= ''
    df['OWASP']=''
    df['OWASP References']=''

    # Reorganizar as colunas
    df = df[['Repository', 'Source', 'fileName', 'Date', 'CWE', 'CVE/GHSA', 'URL', 'Severity', 'Description', 'Solution', 'References', 'filePath', 'Lines', 'Code', 'OWASP', 'OWASP References']]

    # Renomear as colunas
    df = df.rename(columns={'nome_arquivo': 'Repository', 'fileName': 'Vulnerability Class', 'Date': 'data_atual', 'filePath': 'File Path', 'CWE': 'CWE', 'CVE/GHSA': 'CVE/GHSA', 'URL': 'URL', 'Severity': 'Severity', 'Description': 'Description', 'Solution': 'Solution', 'References': 'References'})

    # Salvar o DataFrame como Excel
    nome_saida = f'{nome_arquivo_sem_extensao}.xlsx'
    df.to_excel(nome_saida, index=False)

    print("[INFO] DADOS DO SCAN SCA EXTRAIDOS COM SUCESSO!")

if __name__ == "__main__":
    # Verificar se o nome do arquivo foi fornecido como argumento
    if len(sys.argv) != 2:
        print("Por favor, forneça o nome do arquivo JSON como argumento.")
    else:
        nome_do_arquivo = sys.argv[1]
        processar_json(nome_do_arquivo)
