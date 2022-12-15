from flask import Flask, render_template, request
import ccbhash

app = Flask(__name__)

bbdd = ccbhash.get_db('bbdd.json')
ccbhashes: dict[str, dict[str, ]] = {}
graphs: dict[str, str] = {}
callgraphs: dict[str, str] = {}
scores: list[str] = []
last_cfg: str = ''
last_callgraph: str = ''

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/file', methods = ['GET', 'POST'])
def file():
    if request.method == 'POST':
        global ccbhashes, graphs, callgraphs

        file = request.files.get('file')
        file.save('.last_malware')
        ccbhashes, graphs, callgraphs = ccbhash.calculate_ccbhash_and_graphs('.last_malware')
        func = list(graphs.keys())[0]
        graph = graphs[func]
        fgraph = graph.replace('\n', '<br>').replace('\\', '\\\\')

        return render_template('graph.html', fgraph=fgraph, functions={'functions': list(graphs.keys())}, function=func)

@app.route('/graph', methods = ['GET', 'POST'])
def graph():
    if request.method == 'POST':
        global graphs, last_cfg, last_callgraph

        last_cfg = ''
        last_callgraph = ''

        func = request.form['function']
        graph = graphs[func]
        fgraph = graph.replace('\n', '<br>').replace('\\', '\\\\')

        return render_template('graph.html', fgraph=fgraph, functions={'functions': list(graphs.keys())}, function=func)


@app.route('/similarity', methods = ['GET', 'POST'])
def similarity():
    if request.method == 'POST':
        global ccbhashes, graphs, scores

        func = request.form['function']
        graph1 = graphs[func]
        hash = ccbhashes[func]
        fscores = ccbhash.compare_function(hash, bbdd)
        fscores = dict(sorted(fscores.items(), key = lambda item: item[1], reverse=True))
        scores = [f'{f}: {round(score, 2)}' for f, score in fscores.items()]
        fgraph1 = graph1.replace('\n', '<br>').replace('\\', '\\\\')

        return render_template('similarity.html', fgraph=fgraph1, fgraph2='', functions={'functions': list(graphs.keys())}, function=func, function2=scores[0], scores={'scores': scores[:100]}, graph_type='cfg')

@app.route('/comparison', methods = ['GET', 'POST'])
def comparison():
    if request.method == 'POST':

        global ccbhashes, graphs, scores, last_cfg, last_callgraph

        func = request.form['function']
        family_file_func_score = request.form['function2']
        x = family_file_func_score.split(': ')
        family_file_function = x[0]
        y = family_file_function.split('/')
        family = y[0]
        file = y[1]
        func2 = y[2]
        graph1 = graphs[func]
        fgraph1 = graph1.replace('\n', '<br>').replace('\\', '\\\\')
        last_cfg, last_callgraph = ccbhash.get_graph(func2, f'/Users/pabloperezjimenez/Desktop/DescargasVT/{family}/{file}')
        fgraph2 = last_cfg.replace('\n', '<br>').replace('\\', '\\\\')

        return render_template('similarity.html', fgraph=fgraph1, fgraph2=fgraph2, functions={'functions': list(graphs.keys())}, function=func, function2=family_file_func_score, scores={'scores': scores[:100]}, graph_type='cfg')

@app.route('/change_graph', methods = ['GET', 'POST'])
def change_graph():
    if request.method == 'POST':

        global ccbhashes, graphs, callgraphs, scores, last_cfg, last_callgraph

        func = request.form['function']
        family_file_func_score = request.form['function2']
        graph_type = request.form['graph_type']
        if 'cfg' in graph_type:
            graph1 = graphs[func]
            graph2 = last_cfg
            if graph_type == 'little_cfg':
                graphs1 = graph1.split('\n')
                graph1 = graphs1[0] + '\n'
                for g1 in graphs1[1:]:
                    if any((c.isalnum() or c == ';') for c in g1) and g1.count(u'\u2500') < 10:
                        g1 = ''
                    else:
                        for c in g1:
                            if c.isalnum() or c in (',', '.', ';' '{', '}', '[', ']', '+', '-', '*'): g1 = g1.replace(c, ' ')
                        g1 = f'{g1}\n'
                    graph1 += g1
                graphs2 = graph2.split('\n')
                graph2 = graphs2[0] + '\n'
                for g2 in graphs2[1:]:
                    if any((c.isalnum() or c == ';') for c in g2) and g1.count(u'\u2500') < 10:
                        g2 = ''
                    else:
                        for c in g2:
                            if c.isalnum() or c in (',', '.', ';', '{', '}', '[', ']', '+', '-', '*'): g2 = g2.replace(c, ' ')
                        g2 = f'{g2}\n'
                    graph2 += g2
        else:
            graph1 = callgraphs[func]
            graph2 = last_callgraph
        fgraph1 = graph1.replace('\n', '<br>').replace('\\', '\\\\')
        fgraph2 = graph2.replace('\n', '<br>').replace('\\', '\\\\')

        return render_template('similarity.html', fgraph=fgraph1, fgraph2=fgraph2, functions={'functions': list(graphs.keys())}, function=func, function2=family_file_func_score, scores={'scores': scores[:100]}, graph_type=graph_type)

if __name__ == '__main__':
    app.run(debug=True, host='localhost', port=8000)