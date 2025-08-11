# Leads Tracker (Flask)

Simple web app for sales employees to submit daily lead reports and for a manager to view dashboards and drill-down by employee.

## Quick start

```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt

# Initialize database and create default admin
flask --app app.py init-db

# Run
flask --app app.py run
```

Login as admin:
- email: admin@example.com
- password: Admin123!

Change the admin credentials in the Users page.

## Notes

- Conversion rate excludes fake leads from the denominator.
- Categories: Implants, Orthodontics, Restoration with Endo, Scaling, Veneers, Fake/Unreal.
- Manager can filter by date range, export CSV, and click an employee to view details.
