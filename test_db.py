import urllib.parse
from sqlalchemy import create_engine, text

# Construct the ODBC connection string for SQL Authentication.
odbc_str = (
    "Driver={ODBC Driver 18 for SQL Server};"
    "Server=tcp:remittanceserver.database.windows.net,1433;"
    "Database=RemittanceApp;"
    "Uid=remittanceserver;"
    "Pwd=Sgb3@1017;"
    "Encrypt=yes;"
    "TrustServerCertificate=no;"
    "Connection Timeout=60;"
)

# URL-encode the entire connection string
params = urllib.parse.quote_plus(odbc_str)

# Create the SQLAlchemy connection URL using odbc_connect
DATABASE_URL = f"mssql+pyodbc:///?odbc_connect={params}"
print("Encoded connection string:", DATABASE_URL)

engine = create_engine(DATABASE_URL, echo=True, connect_args={'timeout': 60})

try:
    with engine.connect() as conn:
        # Wrap the query string in text() so it's recognized as executable
        result = conn.execute(text("SELECT 1"))
        print("Connection successful:", result.fetchone())
except Exception as e:
    print("Connection failed:", e)
