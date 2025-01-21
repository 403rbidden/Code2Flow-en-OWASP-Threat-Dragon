from pytm import TM, Actor, Process, Dataflow
from pytm.pytm import Action
import os
import json

# Rutas de los archivos
GV_FILE_PATH = "/home/mj/Documents/Environments/pytm/Documentos/Flujo de datos/Inglés/flujo_datos_diagrama_inglés.gv"
OUTPUT_FILE_PATH = "/home/mj/Documents/Environments/pytm/Documentos/Evidencias/threat_model.json"
TEMPLATE_PATH = "/home/mj/Documents/Environments/pytm/lib/python3.12/site-packages/pytm/templates/dfd.html"

# Verifica si la plantilla existe
if not os.path.exists(TEMPLATE_PATH):
    raise FileNotFoundError(f"La plantilla no se encontró en {TEMPLATE_PATH}")


def parse_gv_file(file_path):
    """
    Analiza un archivo .gv y extrae nodos y relaciones, clasificando actores y procesos.
    """
    import re

    nodes = {}
    edges = []

    with open(file_path, "r", encoding="utf-8") as gv_file:
        for line in gv_file:
            line = line.strip()
            if "->" in line:  # Es una relación (edge)
                source, target = line.split("->")
                source = source.strip().strip(";")
                target = target.strip().strip(";")
                edges.append((source, target))
            elif "[" in line and "]" in line:  # Es un nodo
                # Extraer el ID del nodo y la etiqueta (limpia)
                node_id = line.split("[")[0].strip()
                label_match = re.search(r'label="([^"]+)"', line)
                if label_match:
                    label = label_match.group(1).strip()
                    nodes[node_id] = label

    return nodes, edges


def classify_nodes(nodes):
    """
    Clasifica los nodos en actores y procesos según su etiqueta.
    """
    actors = {}
    processes = {}

    for node_id, label in nodes.items():
        # Clasificar nodos como actores o procesos
        if "user" in label.lower() or "client" in label.lower():
            actors[node_id] = label
        else:
            processes[node_id] = label

    return actors, processes


def gv_to_pytm(file_path):
    # Analiza el archivo .gv
    nodes, edges = parse_gv_file(file_path)
    actors_dict, processes_dict = classify_nodes(nodes)

    # Crear el modelo de amenazas
    tm = TM("Threat Model from GV")
    tm.description = "Modelo de amenazas generado desde un archivo .gv con pytm"
    tm.assumptions = "Este modelo asume que los datos están en un entorno seguro."
    tm.onDuplicates = Action.IGNORE

    # Crear actores
    actors = [Actor(name=label) for label in actors_dict.values()]

    # Crear procesos
    processes = [Process(name=label) for label in processes_dict.values()]

    # Crear flujos de datos
    dataflows = []
    for source, target in edges:
        if source in actors_dict and target in processes_dict:
            dataflows.append(
                Dataflow(Actor(name=actors_dict[source]), Process(name=processes_dict[target]))
            )
        elif source in processes_dict and target in processes_dict:
            dataflows.append(
                Dataflow(Process(name=processes_dict[source]), Process(name=processes_dict[target]))
            )

    # Generar el informe
    try:
        print("Generando el informe del modelo...")
        tm.report(template_path=TEMPLATE_PATH)
        print("Informe generado exitosamente.")
    except Exception as e:
        print(f"Error al generar el informe: {e}")

    # Exportar el modelo a JSON
    try:
        print(f"Exportando el modelo a {OUTPUT_FILE_PATH}...")
        model_data = {
            "name": tm.name,
            "description": tm.description,
            "assumptions": tm.assumptions,
            "actors": [{"name": actor.name} for actor in actors],
            "processes": [{"name": process.name} for process in processes],
            "dataflows": [{"source": flow.source.name, "target": flow.target.name} for flow in dataflows],
        }

        with open(OUTPUT_FILE_PATH, "w", encoding="utf-8") as output_file:
            json.dump(model_data, output_file, indent=4, ensure_ascii=False)
        print("Modelo exportado correctamente.")
    except Exception as e:
        print(f"Error al exportar el modelo: {e}")


if __name__ == "__main__":
    gv_to_pytm(GV_FILE_PATH)


def convert_sets_to_lists(data):
    """
    Recorre un objeto (puede ser un diccionario, lista, o conjunto)
    y convierte todos los conjuntos (set) en listas.
    """
    if isinstance(data, set):
        return list(data)
    elif isinstance(data, dict):
        return {key: convert_sets_to_lists(value) for key, value in data.items()}
    elif isinstance(data, list):
        return [convert_sets_to_lists(item) for item in data]
    else:
        return data


def gv_to_pytm(file_path):
    # Analiza el archivo .gv
    nodes, edges = parse_gv_file(file_path)

    # Crear el modelo de amenazas
    tm = TM("Threat Model from GV")
    tm.description = "Modelo de amenazas generado desde un archivo .gv con pytm"
    tm.assumptions = "Este modelo asume que los datos están en un entorno seguro."
    tm.onDuplicates = Action.IGNORE

    # Crear actores y procesos a partir de nodos
    node_objects = {}
    actors = []
    processes = []
    dataflows = []

    for node_id, label in nodes.items():
        if "user" in label.lower():
            actor = Actor(name=label)
            node_objects[node_id] = actor
            actors.append(actor)
        else:
            process = Process(name=label)
            node_objects[node_id] = process
            processes.append(process)

    # Crear flujos de datos a partir de relaciones
    for source, target in edges:
        if source in node_objects and target in node_objects:
            dataflow = Dataflow(
                node_objects[source],
                node_objects[target],
                name=f"{node_objects[source].name} to {node_objects[target].name}"
            )
            dataflows.append(dataflow)

    # Generar el informe
    try:
        print("Generando el informe del modelo...")
        tm.report(template_path=TEMPLATE_PATH)
        print("Informe generado exitosamente.")
    except Exception as e:
        print(f"Error al generar el informe: {e}")

    # Exportar el modelo a JSON
    try:
        print(f"Exportando el modelo a {OUTPUT_FILE_PATH}...")
        model_data = {
            "name": tm.name,
            "description": tm.description,
            "assumptions": tm.assumptions,
            "actors": [{"name": actor.name} for actor in actors],
            "processes": [{"name": process.name} for process in processes],
            "dataflows": [{"name": flow.name} for flow in dataflows],
        }

        # Convertir todos los sets a listas en el modelo
        model_data_cleaned = convert_sets_to_lists(model_data)

        with open(OUTPUT_FILE_PATH, "w", encoding="utf-8") as output_file:
            json.dump(model_data_cleaned, output_file, indent=4, ensure_ascii=False)
        print("Modelo exportado correctamente.")
    except Exception as e:
        print(f"Error al exportar el modelo: {e}")


if __name__ == "__main__":
    gv_to_pytm(GV_FILE_PATH)
