# Lab 9 —  Analyse de surface d'attaque Android avec Drozer (audit défensif en environnement autorisé)

**Auteur :** DOSSAH Yao Landry  
**Filière :** Génie CyberDefense et Systèmes de Télécommunications Embarquées (GCDSTE)  
**Établissement :** ENSA Marrakech

---

## Contexte pédagogique

Ce laboratoire porte sur l'analyse de la surface d'attaque d'une application Android via **Drozer**. L'objectif est de cartographier les composants Android exposés (Activities, Services, Broadcast Receivers, Content Providers), d'évaluer leurs protections, d'identifier les vulnérabilités de configuration, et de proposer des remédiations conformes aux standards OWASP MASVS. L'analyse est strictement défensive, réalisée sur un émulateur contrôlé avec une application de test fournie.

---

## Environnement

| Composant | Détail |
|-----------|--------|
| IDE | Android Studio |
| Émulateur | AVD API 28-30 |
| Outil d'audit | Drozer (console + agent APK) |
| Application cible | VulnerableApp.apk (`com.example.vulnerableapp`) |
| Standard de référence | OWASP MASVS / MASTG |

---

## Architecture du lab

```
Machine hôte
      │
      │  drozer console connect
      │  Port forwarding TCP 31415
      ▼
Émulateur Android (AVD)
      │
      ├── Drozer Agent (APK) ← serveur embarqué
      │
      └── VulnerableApp.apk
           ├── LoginActivity        (exported=true, sans protection)
           ├── UserProfileActivity  (exported=true, permission faible)
           ├── DataSyncService      (exported=true, sans validation)
           ├── BootReceiver         (exported=true, sans validation)
           └── UserDataProvider     (exported=true, lecture/écriture)
```

---

## Étape 1 — Configuration de l'environnement

```bash
# Installation des APKs sur l'émulateur
adb install drozer-agent.apk
adb install VulnerableApp.apk

# Port forwarding pour Drozer
adb forward tcp:31415 tcp:31415
```

Activer l'option **Embedded Server** dans l'application Drozer Agent sur l'émulateur, puis connecter la console :

```bash
drozer console connect
```

---

## Étape 2 — Cartographie des composants exposés

```bash
# Localiser l'application
dz> run app.package.list -f vulnerable

# Informations générales
dz> run app.package.info -a com.example.vulnerableapp

# Composants exposés
dz> run app.activity.info -a com.example.vulnerableapp
dz> run app.service.info -a com.example.vulnerableapp
dz> run app.broadcast.info -a com.example.vulnerableapp
dz> run app.provider.info -a com.example.vulnerableapp
```

**Résultat — Composants identifiés :**

| Type | Nom | Exporté | Protection |
|------|-----|---------|-----------|
| Activity | `LoginActivity` | Oui | Aucune |
| Activity | `UserProfileActivity` | Oui | Permission faible |
| Service | `DataSyncService` | Oui | Aucune |
| Receiver | `BootReceiver` | Oui | Aucune |
| Provider | `UserDataProvider` | Oui | Lecture/Écriture |

---

## Étape 3 — Analyse des protections

```bash
# Manifest complet
dz> run app.package.manifest com.example.vulnerableapp

# Intent-filters par activité
dz> run app.activity.info -a com.example.vulnerableapp -i

# Permissions des Content Providers
dz> run app.provider.info -a com.example.vulnerableapp -p

# URIs accessibles
dz> run scanner.provider.finduris -a com.example.vulnerableapp
dz> run app.provider.finduri com.example.vulnerableapp
```

**Résultat observé :** plusieurs URIs du `UserDataProvider` sont accessibles sans permission déclarée. `DataSyncService` ne valide pas l'intent reçu. `BootReceiver` accepte n'importe quel broadcast sans vérification de l'action.

---

## Étape 4 — Analyse des risques

| Composant | Risque | Scénario d'abus |
|-----------|--------|----------------|
| `LoginActivity` exportée | Contournement d'authentification | Lancement direct de l'activité via `adb shell am start` sans passer par l'écran de login |
| `UserDataProvider` sans permission | Fuite de données utilisateur | Lecture des URIs exposées depuis une application tierce malveillante |
| `DataSyncService` sans validation | Exécution non autorisée | Démarrage du service pour déclencher une synchronisation non sollicitée |
| `BootReceiver` sans validation | Déclenchement arbitraire | Envoi d'un intent malveillant simulant `BOOT_COMPLETED` |
| Permissions insuffisantes | Protection inadéquate | Composants protégés par des permissions `normal` contournables |

---

## Triage des vulnérabilités

| ID | Composant | Vulnérabilité | Sévérité | Statut |
|----|-----------|--------------|----------|--------|
| V1 | `LoginActivity` | Exportée sans protection | Élevée | À corriger |
| V2 | `UserDataProvider` | URIs accessibles sans permission | Critique | À corriger |
| V3 | `DataSyncService` | Service exporté sans validation d'intent | Moyenne | À corriger |
| V4 | `BootReceiver` | Receiver exporté sans validation | Faible | À surveiller |
| V5 | `UserProfileActivity` | Permission de niveau insuffisant | Moyenne | À corriger |

---

## Mapping OWASP MASVS

| ID | Vulnérabilité | Référence MASVS | Exigence |
|----|--------------|----------------|---------|
| V1 | Activities exportées sans protection | MSTG-PLATFORM-1 | N'exposer que les composants nécessaires |
| V2 | Content Provider mal protégé | MSTG-STORAGE-2 | Aucune donnée sensible sans protection adéquate |
| V3 | Service sans validation d'intent | MSTG-PLATFORM-2 | Valider les entrées de sources externes |
| V4 | Receiver sans validation | MSTG-PLATFORM-3 | Valider les intents reçus |
| V5 | Permissions insuffisantes | MSTG-AUTH-1 | Mécanismes d'authentification robustes |

---

## Remédiations

### 1. Activities — passer `exported=false` pour les composants internes

```xml
<!-- UserProfileActivity : non accessible depuis l'extérieur -->
<activity android:name=".UserProfileActivity" android:exported="false" />
```

### 2. Content Provider — ajouter une permission `signature`

```xml
<permission
    android:name="com.example.vulnerableapp.permission.READ_USER_DATA"
    android:protectionLevel="signature" />

<provider
    android:name=".UserDataProvider"
    android:authorities="com.example.vulnerableapp.provider.userdata"
    android:exported="true"
    android:permission="com.example.vulnerableapp.permission.READ_USER_DATA" />
```

### 3. Service — valider l'intent avant traitement

```java
@Override
public int onStartCommand(Intent intent, int flags, int startId) {
    if (intent == null || !isValidIntent(intent)) {
        stopSelf();
        return START_NOT_STICKY;
    }
    // Suite du traitement...
}
```

### 4. Broadcast Receiver — vérifier l'action reçue

```java
@Override
public void onReceive(Context context, Intent intent) {
    if (intent == null || !Intent.ACTION_BOOT_COMPLETED.equals(intent.getAction())) {
        return;
    }
    // Suite du traitement...
}
```

### 5. Permissions personnalisées — utiliser `protectionLevel="signature"`

```xml
<permission
    android:name="com.example.vulnerableapp.permission.DATA_SYNC"
    android:protectionLevel="signature" />
```

---

## Points clés retenus

- `exported=true` sans permission ni validation d'intent est la vulnérabilité la plus fréquente dans les applications Android mal configurées — elle expose directement les composants à toute application tierce installée sur l'appareil.
- Les Content Providers sont particulièrement sensibles : une URI accessible sans permission permet la lecture ou la modification de données applicatives sans aucune interaction utilisateur.
- `protectionLevel="signature"` garantit que seules les applications signées avec le même certificat peuvent utiliser la permission — c'est le niveau recommandé pour les permissions inter-composants internes.
- Drozer opère en boîte noire depuis l'extérieur de l'application — il reproduit exactement ce qu'une application malveillante installée sur le même appareil pourrait faire.
- La validation d'intent dans `onReceive()` et `onStartCommand()` est indispensable même quand `exported=false` est difficile à appliquer (cas des receivers système comme `BOOT_COMPLETED`).

---

*Lab réalisé dans le cadre du cours Sécurité des Applications Mobiles — ENSA Marrakech, Filière GCDSTE*
