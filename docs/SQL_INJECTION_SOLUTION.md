# TP Injection SQL — Fiche de Rendu Étudiant (Student Submission Evidence)

**Cours** : Application Security Capstone  
**Défi** : Détection et correction d'une injection SQL dans le moteur de recherche d'incidents (`Incident search`)  
**Fichiers concernés** : `training/search.py`, `training/tests/test_hardening.py`  

---

## 1. Description de la cause racine et impact sur la confidentialité

### A. Cause racine
La vulnérabilité résidait dans le fichier `training/search.py` au niveau de la fonction `search_incidents` :
```python
sql = (
    "SELECT id, title, description FROM incidents_incident "
    f"WHERE created_by_id = {int(user_id)} AND title LIKE '%{query}%' "
    "ORDER BY created_at DESC LIMIT 20"
)
cursor.execute(sql)
```
La variable utilisateur `query` issue de la requête HTTP GET (`?q=...`) était directement concaténée dans la chaîne SQL sans aucune paramétrisation ni échappement.

### B. Impact sur la confidentialité (Confidentiality Impact)
Bien que la directive SQLite `PRAGMA query_only = ON` empêchât toute altération des données (*Data Tampering*), cette faille permettait une **rupture totale de la confidentialité multi-utilisateurs (BOLA / Broken Object-Level Authorization)** :
Un utilisateur authentifié standard (*Alice*) pouvait extraire les incidents privés et confidentiels de tiers (*Bob*), violant ainsi le principe fondamental d'isolation des données de l'application.

---

## 2. Analyse détaillée de l'expression WHERE injectée

Lorsque l'attaquant injecte le payload :
```text
%' OR 1=1 -- 
```

La requête SQL finale construite et exécutée par SQLite devient :
```sql
SELECT id, title, description FROM incidents_incident 
WHERE created_by_id = 1 AND title LIKE '%%' OR 1=1 -- %' ORDER BY created_at DESC LIMIT 20
```

### Décomposition technique :
1. **Fermeture de la chaîne littérale** : L'apostrophe `'` contenue dans `%'` ferme la valeur de comparaison du prédicat `LIKE '%%'`.
2. **Évaluation booléenne tautologique** : La clause `OR 1=1` est évaluée au même niveau logique que la condition d'appartenance `created_by_id = 1`. Puisque `1=1` est toujours VRAI, l'ensemble de la condition `WHERE` devient vraie pour **tous** les enregistrements de la table, annulant le filtre sur `created_by_id`.
3. **Commentaire de fin de requête** : Le double tiret `-- ` transforme tout le reste de la requête originale (`%' ORDER BY created_at DESC LIMIT 20`) en commentaire ignoré par le parseur SQLite, évitant ainsi toute erreur de syntaxe sur l'apostrophe fermante résiduelle.

---

## 3. Preuves de l'exploitation (Avant correction)

### A. Requête HTTP & Découverte manuelle
- **Requête** : `GET /training/search/?q=%25%27+OR+1%3D1+--+ HTTP/1.1` (avec session `lab-alice`)
- **Résultat dans la page HTML reçue** :
```html
<h2>Search results</h2>
<p>2 results</p>
<article><h3>Alice laptop</h3><p>ALICE_OWN_FIXTURE</p></article>
<article><h3>Bob network</h3><p>BOB_PRIVATE_FIXTURE</p></article>
```
L'enregistrement confidentiel de Bob (`BOB_PRIVATE_FIXTURE`) est divulgué à Alice.

### B. Échec des tests de durcissement avant correction
Commande exécutée :
```bash
python manage.py test training.tests.test_hardening --settings=config.settings.security_lab
```
Résultat : **2 échecs sur 5 tests** :
```text
Creating test database for alias 'default'...
..F.F
======================================================================
FAIL: test_injected_boolean_does_not_disclose_another_owner (training.tests.test_hardening.SearchHardeningTests)
AssertionError: 1 != 0 : 'BOB_PRIVATE_FIXTURE' unexpectedly found in response

======================================================================
FAIL: test_quote_is_data_not_database_error (training.tests.test_hardening.SearchHardeningTests)
AssertionError: 1 != 0 : 'Training database error:' unexpectedly found in response
----------------------------------------------------------------------
Ran 5 tests in 11.441s
FAILED (failures=2)
```

---

## 4. Code Diff de Remédiation

Dans `training/search.py`, la construction SQL brute a été remplacée par une requête via l'ORM Django sécurisé :

```diff
--- a/training/search.py
+++ b/training/search.py
@@ -1,24 +1,11 @@
-"""Deliberate SQLi sink for the local synthetic exercise only."""
+"""Remediated incident search using the Django ORM."""
 from django.db import connection
+from incidents.models import Incident
 
 def search_incidents(user_id, query):
     if connection.vendor != "sqlite":
         raise RuntimeError("The insecure exercise requires its isolated SQLite database.")
-    with connection.cursor() as cursor:
-        cursor.execute("PRAGMA query_only")
-        previous = cursor.fetchone()[0]
-        cursor.execute("PRAGMA query_only = ON")
-        try:
-            sql = (
-                "SELECT id, title, description FROM incidents_incident "
-                f"WHERE created_by_id = {int(user_id)} AND title LIKE '%{query}%' "
-                "ORDER BY created_at DESC LIMIT 20"
-            )
-            cursor.execute(sql)
-            return [{"id": row[0], "title": row[1], "description": row[2]} for row in cursor.fetchmany(20)]
-        finally:
-            cursor.execute(f"PRAGMA query_only = {int(previous)}")
+    return list(
+        Incident.objects.filter(created_by_id=user_id, title__contains=query)
+        .order_by("-created_at")
+        .values("id", "title", "description")[:20]
+    )
```

---

## 5. Preuves après Remédiation

### A. Rejeu du payload injecté
- **Requête** : `GET /training/search/?q=%25%27+OR+1%3D1+--+ HTTP/1.1`
- **Résultat** : 
  - La chaîne `%' OR 1=1 -- ` est traitée comme une valeur littérale de recherche.
  - Aucun incident de Bob n'est retourné.
  - La recherche légitime `q=laptop` retourne uniquement l'incident d'Alice.

### B. Validation du Gate de durcissement (5/5 PASS)
Commande exécutée :
```bash
python manage.py test training.tests.test_hardening --settings=config.settings.security_lab
```
Résultat :
```text
Creating test database for alias 'default'...
.....
----------------------------------------------------------------------
Ran 5 tests in 8.979s

OK
Destroying test database for alias 'default'...
```

---

## 6. Preuve de confinement en Production

Pour garantir qu'aucune vulnérabilité de laboratoire ne puisse être exposée sur un serveur public ou sur Vercel :
1. **Exclusion des URLs** : Le fichier principal [`config/urls.py`](../config/urls.py) n'inclut la route `training/` que si `settings.TRAINING_MODE == True`.
2. **Refus en production** : Dans [`config/settings/production.py`](../config/settings/production.py), `TRAINING_MODE` est hardcodé à `False`.
3. Toute requête vers `/training/search/` sur une instance de production renvoie un code HTTP **404 Not Found**.
