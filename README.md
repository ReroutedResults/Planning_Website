# RR Planning Intelligence

RR Planning Intelligence is a private map and search tool for agricultural and renewables **planning permissions** in Ireland. It covers every council and is refreshed automatically each week.

- There are 9 sections (Dairy/milking, Cow housing, Slurry, Farm buildings, Calving/calves, Feed, Milk storage, Yards/infrastructure, Renewables). Each has its own password, and one master password opens them all.
- It shows only permissions: retention applications, and any application whose description mentions retention, are left out. Section 5 declarations and extensions of duration are left out too.
- The list builds up over time. Each week's new applications are added and nothing is removed. Applications added in the latest update are marked **New**.
- Each section has an interactive map (street or satellite view), keyword search, filters (matched phrase, council, date received, outcome), an "only in map view" option and a CSV export for spreadsheets.
- Every Monday morning a GitHub Action collects the **last week** of applications from the national planning database and adds them to the site. You don't need to do anything.

## How the passwords protect the data

Each section's results are stored **encrypted** (AES-256). Only the correct password can unlock them in the browser. Someone who reads the website's files sees scrambled data and can't read the applications without a password.

The passwords themselves never appear in the site's code. They're stored as GitHub **secrets**, which the weekly update uses to encrypt the data.

Once someone unlocks a section, it stays open until they close that browser tab or click **Lock all**.

---

## Setup (about 15 minutes, one time only)

### 1. Create the repository

1. Sign in at [github.com](https://github.com). Click **+** (top right), then **New repository**.
2. Name it, e.g. `rr-planning`, choose **Public** and click **Create repository**.
   *(Free GitHub Pages needs a public repository. The application data is encrypted, but the search phrases in `config/categories.json` can be read by anyone who finds the repository. To keep those private as well, use a Private repository, which needs a GitHub Pro plan for Pages.)*

### 2. Upload the files

1. On the new repository page, click **uploading an existing file**.
2. Unzip `rr-planning-intelligence.zip` and drag **everything inside the folder** into the upload box, including the `.github`, `config`, `scripts` and `data` folders.
3. Click **Commit changes**.

> On a Mac, the `.github` folder may be hidden in Finder. Press **Cmd + Shift + .** to show it. If it didn't upload, click **Add file → Create new file**, type `.github/workflows/update.yml` as the name, paste in that file's contents and commit.

### 3. Add the 10 passwords as secrets

Go to **Settings → Secrets and variables → Actions**. For each secret below, click **New repository secret**, enter the name exactly as shown, type your chosen password as the value and click **Add secret**.

| Secret name | Unlocks |
|---|---|
| `RR_PW_MASTER` | Every section |
| `RR_PW_DAIRY` | Dairy / milking |
| `RR_PW_COW_HOUSING` | Cow housing |
| `RR_PW_SLURRY` | Slurry |
| `RR_PW_FARM_BUILDINGS` | Farm buildings |
| `RR_PW_CALVING` | Calving / calves |
| `RR_PW_FEED` | Feed |
| `RR_PW_MILK_STORAGE` | Milk storage |
| `RR_PW_YARDS` | Yards / infrastructure |
| `RR_PW_RENEWABLES` | Renewables |

Use a different password for each section, at least 10 characters long. Keep a copy in a password manager, because GitHub won't show a secret again once it's saved.

### 4. Run the first data update

1. Open the **Actions** tab. If GitHub asks, click **I understand my workflows, go ahead and enable them**.
2. Click **Weekly data update** on the left, then **Run workflow → Run workflow**.
3. This first run also fills in the last 12 months of applications so the site doesn't start empty. Wait 2–5 minutes until the run shows a green tick. A red cross usually means a secret is missing or misspelt. Click into the run to see which one.

### 5. Turn on the website

1. Go to **Settings → Pages**.
2. Under **Build and deployment**, set **Source** to *Deploy from a branch*, **Branch** to `main` and the folder to `/ (root)`, then click **Save**.
3. After about a minute your site will be live at `https://<your-username>.github.io/rr-planning/`.

That's it. From now on, every Monday at 05:00 UTC (6am Irish time in summer, 5am in winter), the previous week's applications are added.

---

## Everyday tasks

**Collect the latest applications now:** go to **Actions → Weekly data update → Run workflow**. Running it more than once is safe. An application that's already on the site is never added twice, but its details (e.g. a new decision) are updated.

**Change a password:** update the secret (Settings → Secrets → click the secret → *Update*), then run the workflow. The old password stops working as soon as the run finishes.

> ⚠️ Don't change a section's password **and** the master password in the same week. The update needs one of the two old passwords to open the history it has collected so far. If both have changed, that section's history is lost and it starts again from that week. Change one, run the workflow, then change the other.

**Add or remove search phrases:** edit `config/categories.json` on GitHub (open the file and click the pencil icon), commit, then run the workflow. New phrases apply from the next update onwards.

**Change how much each update collects:** in the same file, `"daysBack": 7` is the number of days each weekly run looks back. `"firstRunMonths": 12` is how much history the very first run fills in (set it to `0` to start from just the last week).

**Use your own domain (e.g. planning.rrexample.ie):** go to **Settings → Pages → Custom domain**. At your domain provider, add a `CNAME` record pointing to `<your-username>.github.io`, then tick **Enforce HTTPS**.

## Good to know

- GitHub pauses scheduled workflows in repositories with no activity for 60 days. The weekly update commits new data every week, which keeps the repository active. If GitHub ever emails you that it has disabled the workflow, click **Enable** on the Actions tab.
- Each council records decisions in its own wording, so the Granted / Refused / Pending labels come from keyword rules. Always check the council's planning file (linked on each application) for the official record.
- Councils sometimes upload applications to the national database a few days after they're received. If you find the odd late one being missed, set `"daysBack"` to `10` or `14`. The overlap won't create duplicates.
- Phrases match anywhere in the development description, so "cubicles" also matches "cubicle shed". An application that matches several phrases appears once and lists every phrase it matched.
- Source: [National Planning Applications](https://data.gov.ie/dataset/national-planning-applications), Department of Housing, Local Government and Heritage (CC BY 4.0).

## Files

```
index.html, styles.css, app.js     the website
config/categories.json             sections and their search phrases
scripts/build.mjs                  weekly data fetch and encryption (Node 20, no packages)
.github/workflows/update.yml       the weekly schedule
data/                              encrypted data, written and added to by the workflow
```
