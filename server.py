import streamlit as st
import pandas as pd
from sklearn.preprocessing import MinMaxScaler,LabelEncoder,OneHotEncoder
import joblib



#from tensorflow.keras.models import load_model


def pre_processing(df) :
    # Select the columns to normalize (assuming all are numeric)
    numeric_cols = df.select_dtypes(include=['float64', 'int64']).columns.tolist()

    # Create a scaler object
    scaler = MinMaxScaler()

    # Fit the scaler on the selected columns
    scaler.fit(df[numeric_cols])

    # Transform the selected columns using the scaler
    df[numeric_cols] = scaler.transform(df[numeric_cols])
    
    categorical_columns=['protocol_type', 'service', 'flag']
    df_categorical_values = df[categorical_columns]
    unique_protocol=sorted(df.protocol_type.unique())
    string1 = 'Protocol_type_'
    unique_protocol2=[string1 + x for x in unique_protocol]
    # service
    unique_service=sorted(df.service.unique())
    string2 = 'service_'
    unique_service2=[string2 + x for x in unique_service]
    # flag
    unique_flag=sorted(df.flag.unique())
    string3 = 'flag_'
    unique_flag2=[string3 + x for x in unique_flag]
    # put together
    dumcols=unique_protocol2 + unique_service2 + unique_flag2
    #print(dumcols)

    df_categorical_values_enc=df_categorical_values.apply(LabelEncoder().fit_transform)
    enc = OneHotEncoder()
    df_categorical_values_encenc = enc.fit_transform(df_categorical_values_enc)
    df_cat_data = pd.DataFrame(df_categorical_values_encenc.toarray(),columns=dumcols)

    df=df.join(df_cat_data)
    df.drop('flag', axis=1, inplace=True)
    df.drop('protocol_type', axis=1, inplace=True)
    df.drop('service', axis=1, inplace=True)
    correlated_cols=['lnum_compromised', 'same_srv_rate', 'dst_host_srv_diff_host_rate', 'srv_serror_rate',
         'service_ftp', 'flag_SF', 'dst_host_srv_serror_rate', 'count', 'flag_S0', 'dst_host_srv_count',
         'dst_host_diff_srv_rate', 'service_http', 'logged_in', 'service_eco_i', 'rerror_rate', 
         'flag_REJ', 'srv_count', 'hot', 'is_guest_login', 'dst_host_same_srv_rate', 'diff_srv_rate',
             'dst_host_count', 'service_private', 'serror_rate', 'Protocol_type_tcp',
             'dst_host_serror_rate', 'Protocol_type_udp', 'lnum_root', 'srv_rerror_rate', 
             'service_other', 'Protocol_type_icmp', 'service_ecr_i', 'dst_host_same_src_port_rate',
             'dst_host_rerror_rate', 'lsu_attempted', 'dst_host_srv_rerror_rate']
    df = df.drop(correlated_cols, axis=1)

    return df 


# Load the IDS model
def load_model_kdd():
    model = joblib.load('mlp_model_kdd.joblib')
    return model

def load_model_2018():
    model = joblib.load('mlp_model_2018.joblib')
    return model

# Define the user interface using Streamlit
def user_interface():
    st.title("Intrusion Detection System")
    st.subheader("Upload the Data:")
    log_file = st.file_uploader("data", type=["csv"])
    if st.button("Run IDS"):
        if log_file:
            st.write("Running IDS model...")
            # Load the log file
            log = pd.read_csv(log_file)
            # Perform pre-processing on the log file
            #log_scaled=pre_processing(log)
            #print(log_scaled.columns)
            # Load the IDS model and predict on the log file
            
            
            model = load_model_kdd()
            predictions = model.predict(log)
            category_dict = {0:'normal',1:'probe',2:'dos',3:'u2r',4:'r2l'}
            #predictions[0] = [category_dict[x] for x in predictions[0]]
            predictions = [category_dict[val] for val in predictions]

            #print(predictions)

            # Display the results
            st.subheader("IDS Results")
            st.write(predictions)
            st.write(type(predictions))
        else:
            st.warning("Please upload your data.")
    
    if st.button("Run CSE-CIC") :
        if log_file :
            st.write("Running CSE-CIC model...")
            # Load the log file
            log = pd.read_csv(log_file)

            model = load_model_2018()
            predictions = model.predict(log)
            category_dict = {0:'normal',1:'Bot',2:'Bruteforce',3:'DDos',4:'DoS',5:'Infilteration',6:'web'}
            #predictions[0] = [category_dict[x] for x in predictions[0]]
            predictions = [category_dict[val] for val in predictions]

            #print(predictions)

            # Display the results
            st.subheader("CSE-CIC Results")
            st.write(predictions)
            st.write(type(predictions))
        else:
            st.warning("Please upload your data.")


# Run the IDS model
def run_ids():
    user_interface()

# Display the results
if __name__ == "__main__":
    run_ids()