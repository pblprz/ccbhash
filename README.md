# CCBHash (Compound Code Block Hash)

## Objetivo

El objetivo de esta herramienta es crear un ***fuzzy hash*** capaz de complementar o incluso sustituir a algunos de los ya existentes como SSDEEP o TLSH.

Con ella podemos calcular el ***fuzzy hash*** tanto de las funciones de un fichero, como del fichero completo, pudiendo comparar las funciones de varios ficheros para determinar si alguna de las funcionas es maliciosa y, a su vez, comparar varios ficheros para ver si alguno es malicioso.

Un *hash* no es más que una función matemática que resume una gran cantidad de bits (o bytes) en unos pocos. Una de las características de los *hashes* es que dos conjuntos de bytes que son exactamente iguales excepto en un bit, deben dar lugar a dos *hashes* totalmente diferentes. Por el contrario, un ***fuzzy hash*** es un *hash* en cuanto resume una gran cantidad de bits en unos pocos pero, en este caso, dos conjuntos de bytes parecidos deben dar lugar a dos ***fuzzy hashes*** muy parecidos o incluso iguales.

Nuestro *hash* llamado **CCBHash** (Compound Code Block Hash) se compone de 16 bytes y se han demostrado resultados prometedores que mejoran a ***fuzzy hashes*** consolidados como SSDEEP o TLSH. Para más información, esta propuesta fue presentada en la RECSI 2022, por lo que se pueden consultar las actas de dicho congreso.

Actas del congreso: https://recsi2022.unican.es/wp-content/uploads/2022/10/LibroActas-978-84-19024-14-5.pdf

Diapositivas de CCBHash en el congreso: https://recsi2022.unican.es/wp-content/uploads/2022/11/Pablo-Perez-CCBHash-Compound-Code-Block-Hash-para-Analisis-de-Malware.pdf

## Funcionamiento

El único fichero realmente necesario es `ccbhash.py`.
El resto de ficheros componen la interfaz gráfica que, en este caso, no es necesaria.
La versión de Python utilizada es la 3.9.0.

Para usar `ccbhash.py` lo descargamos y desde un script de Python se ejecuta: `import ccbhash`

Para utilizar la interfaz gráfica:
1. Se despliega el backend ejecutando en: `python3 index.py`
2. Se abre en el navegador la dirección por defecto: `http://localhost:8000`
3. Se interactúa con la interfaz tal y cómo se indica en el frontend
