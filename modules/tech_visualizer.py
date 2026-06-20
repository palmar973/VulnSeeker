import networkx as nx
import matplotlib.pyplot as plt
from matplotlib.figure import Figure
import logging

logger = logging.getLogger("VulnSeeker.Visualizer")


class TechVisualizer:
    def generate_map(self, tech_list: list, waf_name: str, subdomains_count: int) -> Figure:
        """
        Genera un grafo de arquitectura basado en el reconocimiento.
        Estilo: Dark/Cyberpunk sin emojis para compatibilidad.
        """
        G = nx.DiGraph()

        # Nodos base sin emojis
        user_node = "USER (Client)"
        internet_node = "INTERNET"

        G.add_node(user_node, type='user')
        G.add_node(internet_node, type='net')
        G.add_edge(user_node, internet_node)

        current_source = internet_node

        # Capa WAF
        if waf_name and waf_name.lower() != "none" and waf_name.lower() != "unknown":
            waf_node = f"WAF: {waf_name}"
            G.add_node(waf_node, type='waf')
            G.add_edge(current_source, waf_node)
            current_source = waf_node

        # Capa Frontend / Subdominios
        if subdomains_count > 0:
            dns_node = f"DNS / SUBS ({subdomains_count})"
            G.add_node(dns_node, type='infra')
            G.add_edge(current_source, dns_node)
            current_source = dns_node

        # Capa Web Server (Nginx, Apache...)
        server_found = False
        for tech in tech_list:
            if tech.lower() in ['nginx', 'apache', 'iis', 'litespeed', 'cloudflare']:
                server_node = f"SERVER: {tech}"
                G.add_node(server_node, type='server')
                G.add_edge(current_source, server_node)
                current_source = server_node
                server_found = True
                break  # Solo graficamos el principal

        if not server_found:
            server_node = "WEB SERVER (?)"
            G.add_node(server_node, type='server')
            G.add_edge(current_source, server_node)
            current_source = server_node

        # Capa Aplicación (CMS / Lenguaje)
        app_node_name = "APP / CMS"
        # Buscamos algo relevante para nombrar el nodo
        relevant_apps = [t for t in tech_list if t.lower() not in ['nginx', 'apache', 'iis', 'cloudflare']]
        if relevant_apps:
            app_node_name = f"APP: {relevant_apps[0]}"  # Tomamos la primera app detectada (ej: Django, WordPress)

        G.add_node(app_node_name, type='app')
        G.add_edge(current_source, app_node_name)

        # Capa Base de Datos (Inferida)
        db_node = "DATABASE (?)"
        tech_str = " ".join(tech_list).lower()

        if "wordpress" in tech_str or "joomla" in tech_str or "php" in tech_str:
            db_node = "MySQL / MariaDB"
        elif "django" in tech_str or "python" in tech_str or "postgresql" in tech_str:
            db_node = "PostgreSQL"
        elif "asp" in tech_str or "net" in tech_str:
            db_node = "SQL Server"
        elif "mongo" in tech_str or "express" in tech_str:
            db_node = "MongoDB"

        G.add_node(db_node, type='db')
        G.add_edge(app_node_name, db_node)

        # Crear Figura sin usar pyplot global para evitar conflictos
        fig = Figure(figsize=(10, 8), facecolor='#0D1117')  # Fondo oscuro UI
        ax = fig.add_subplot(111)
        ax.set_facecolor('#0D1117')

        # Layout Jerárquico (Árbol) o Spring
        try:
            # Intentamos crear una jerarquía manual
            pos = nx.spring_layout(G, seed=42, k=0.9)
        except:
            pos = nx.random_layout(G)

        # Colores según tipo de nodo
        node_colors = []
        for node in G.nodes():
            n_type = G.nodes[node].get('type', 'default')
            if n_type == 'user':
                color = '#8b949e'  # Gris
            elif n_type == 'net':
                color = '#58a6ff'  # Azul claro
            elif n_type == 'waf':
                color = '#da3633'  # Rojo Alerta
            elif n_type == 'server':
                color = '#1f6feb'  # Azul Servidor
            elif n_type == 'app':
                color = '#238636'  # Verde oscuro legible
            elif n_type == 'db':
                color = '#d29922'  # Naranja DB
            elif n_type == 'infra':
                color = '#8b949e'
            else:
                color = '#238636'
            node_colors.append(color)

        # Dibujar
        nx.draw_networkx_nodes(G, pos, ax=ax, node_color=node_colors, node_size=2500, edgecolors='#30363d')
        nx.draw_networkx_edges(G, pos, ax=ax, edge_color='#8b949e', arrows=True, arrowsize=20, width=1.5)

        # Etiquetas (Texto Blanco)
        nx.draw_networkx_labels(G, pos, ax=ax, font_color='white', font_size=9, font_weight='bold',
                                font_family='sans-serif')

        # Eliminar bordes del gráfico
        ax.axis('off')
        fig.tight_layout()

        return fig
