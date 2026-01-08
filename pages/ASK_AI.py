import streamlit as st
import pandas as pd
import sqlite3
from langchain_experimental.agents import create_pandas_dataframe_agent
from langchain_groq import ChatGroq
import os
from dotenv import load_dotenv

load_dotenv()
st.markdown("""
    <style>
    /* Main Background with a soft warm tint */
    .stApp {
        background-color: #FFF9F2; 
    }
    /* Colorful header for the sidebar */
    [data-testid="stSidebar"] {
        background-image: linear-gradient(#2E3192, #1BFFFF);
        color: white;
    }
    /* Metric Cards Styling */
    [data-testid="stMetric"] {
        background-color: #ffffff;
        padding: 15px;
        border-radius: 15px;
        box-shadow: 5px 5px 15px rgba(0,0,0,0.05);
        border-left: 5px solid #FF9933; /* Saffron accent */
    }
    /* Force text to be Dark Gray/Black */
    header{
    background-color: #FFF9F2 !important;
    color: #000000 !important;
    font-family: 'Inter', sans-serif;
    }
    [data-testid="stIconMaterial"]{
    color: rgba(0,0,0) !important;
    background-color: rgba(0,0,0,0) !important;
    }
    .st-emotion-cache{
    color: #000000 !important;
    }

    /* 3. Specifically Target Headers */
    h1, h2, h3, h4, h5, h6 {
        color: #1A202C !important;
    }

    /* 4. Fix Metric Labels & Values (The blue/white issue) */
    [data-testid="stMetricLabel"] {
        color: #4A5568 !important; /* Muted dark gray */
    }
    [data-testid="stMetricValue"] {
        color: #2D3748 !important; /* Bold dark gray */
    }

    /* 5. Make the Sidebar text dark if the background is light */
    [data-testid="stSidebarNav"] span {
        color: #2D3748 !important;
        font-weight: 500;
    }
    </style>
    """, unsafe_allow_html=True)

st.set_page_config(page_title="NetraFlow", page_icon="👁",layout="wide")
st.title('ASK AI')

current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(current_dir)
db_path = os.path.join(project_root, "logs_", "traffic_security.db")

def load_data():
    # Ensure this path matches your SecuritySystem db_path
    conn = sqlite3.connect(db_path)
    df = pd.read_sql_query("SELECT * FROM vehicle_logs", conn)
    # Convert timestamp to datetime objects for plotting
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    conn.close()
    return df

try:
    df = load_data()
except Exception as e:
    st.error(f"Could not connect to database: {e}")
    st.stop()

agent = None

if df is not None:
    st.write("Provide a concise and helpful prompt for suitable insights...")
    question = st.text_input("Enter your question")

    @st.cache_resource
    def create_agent(df):
            prefix = """
            You are a traffic data expert. You are working with a pandas dataframe named `df`.
            The columns are: timestamp, vehicle_id, type, color, is_suspicious, and s3_key.
            If the user asks for a count, use the vehicle_id column. 
            Always provide a concise and helpful answer.
            """

            llm = ChatGroq(
                temperature=0,
                model_name="llama-3.3-70b-versatile",
                groq_api_key=st.secrets["GROQ_API_KEY"]
            )
            return create_pandas_dataframe_agent(
                llm,
                df,
                verbose=True,
                allow_dangerous_code=True,
                prefix=prefix,  # Helping the AI understand the context
                handle_parsing_errors=True
            )


    if question:
        agent = create_agent(df)

        with st.spinner('🔍 Analyzing traffic logs...'):
            try:

                response = agent.invoke(question)

                st.write("### Answer:")

                # Extract the output
                if isinstance(response, dict):
                    output_text = response.get("output", "I couldn't find an answer.")
                    st.success(output_text)
                else:
                    st.success(str(response))
            except Exception as e:
                # Better debugging for you
                st.error("Check the API key")
                st.write(e)