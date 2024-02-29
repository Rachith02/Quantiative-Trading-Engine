// main.cpp
// all the important codes should be down here


#include <iostream>
#include <httplib.h>
#include <websocket.h>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <quantlib.hpp>
#include <future>
#include <vector>
#include <string>
#include <fstream>
#include <sstream>
#include <cmath>
#include <algorithm>
#include <iomanip>
#include <chrono>
#include <ctime>

#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>

#include <openssl/ssl.h.in>
#include <openssl.err.h.in>

#include <spdlog/spdlog.h>



using namespace std;

bool validateStrategy( const string& strategyScript ){

    if(strategyScript.empty()){           // Ensure that strategy is not empty
        cerr << "Error: Empty strategy script" << endl;
        return false;
    }

    if (strategyScript.find("buy") == string::npos){    //npos is used to represent the largest possible value of the size_t
        cerr << "Error: Missing 'buy' keyword in strategy script" << endl;
        return false;
    }

    if( strategyScript.find("sell") == string::npos){
        cerr << "Error: Missing 'sell' keyword in strategy script" << endl;
        return false;
    }

    if( strategyScript.find("symbol") == string::npos){
        cerr << "Error: Missing 'symbol' keyword in strategy script" << endl;
        return false;
    }

    return true;

}


class DistributedStretegyManager{
public:
    void deployStrategy(const string& strategyScript, const string& targetNode){

        cout << "Deploying stretegy on node" << targetNode << ": " << strategyScript << endl;

    }

};

DistributedStretegyManager disStrManager;

class Strategy {
public:
    void evaluate(){
        cout << "Evaluating strategy..." << endl;
    }    
};



class MarketDataFeed {
public:
    void processMarketData(){
        cout << "Processing market data..." << endl;
    }    
};


void executeOrder( int order) {
    cout << "Executing Order: " << order << endl;
}

string getCurrentTimestamp() {

    auto now = chrono::system_clock::now();
    auto time_point = chrono::system_clock::to_time_t(now);         // this function uses the <chrono> library to get the current systemtime, converts it to a time_point and then converts that time_point to a string using ctime. The resulting string is the current timestamp
    return ctime(&time_point);                                                                      

}




void deploystrategy( const string& strategyScript){
    if(strategyScript.empty()){
        throw invalid_argument("Empty strategy script");            //throw keyword is used ro raise an exception in C++
    }

    try{
        quantlib::deployStrategy(strategyScript);

        ofstream logFile("trading_log.txt", ios::app);     // opens an output file stream to in append mode
        logFile << "Strategy deployed - " << getCurrentTimestamp() << "\n";
        logFile.close();

    }
    catch( const exception& e) {
        cerr << "Error during strategy deployment: " << e.what() << endl;    // prints the error massage

        ofstream errorLogFile("error_log.txt", ios::app);           // opens an error log file stream to error_log.txt in append mode
        errorLogFile << "Error during strategy deployment: " << e.what() << endl;
        errorLogFile << "Error during strategy deployment - " << getCurrentTimestamp << ": " << e.what() << "\n";   // logs the error massage along with the current time stamp to the error log file
        errorLogFile.close();
    }
}

void handleDeployement(const httplib::Request& req, httplib::Response& res){

    string strategyScript = req.get_param_value("script");          //get_param_value is a method provided by httplib library
    string targetNode = req.get_param_value("node");                // this method retrieves the value of the data named node from teh requests query string or form data

    disStrManager.deployStrategy(strategyScript,targetNode);

    res.set_content("Strategy deployed on node" + targetNode + ". Monitoring...", "text/plain");


    try{
        string stretegyScript = req.get_param_value("Script");     // this req.get_param_value is used to extract a parameter named script from the HTTP request

        res.set_content("Strategy deployed. Monitoring...", "text/plain");    // sets the response of strategy deployed monitoring.. and used to set the content of th HTTP response

    }
    catch( const exception& e){
        res.status = 500;
        res.set_content("Internal Server Error: " + string(e.what()), "text/plain");   //this what() member function returns a string describing the exception. the what() function is commonly used to obtain more information about the exception
    }    // this is an exception. this sets the HTTP response status to 500 and send an error massage in the response

    //Logging Errors

    catch(const exception& e){
        cerr << "Error during strategy deployment: " << e.what() << endl;     // cout and cin like cerris for standant error and that massage goes to standard error system

        res.status = 500;
        res.set_content("Internal Server Error", "text/plain");
    }

    //Specific Error Handling
    catch (const invalid_argument& e){                 // this invalid_argument is an exception class derived from logic_error class. it is typically used to indicate that a function recieved an argument of invald value
        cerr << "Invalid Arguemnt error: " << e.what() << endl;          

        res.status = 400;
        res.set_content("Bad Reques: Invalid arguemnt", "text/plain");
    }
}

// 2.Logging

void logMassage( const string& massage){
    cout << "LOG: " << massage << endl;
}

void deployStrategy( const string& strategyScript){
    try{
        QuantLib::deployStrategy(strategyScript);   // Implementing strategy deployment logic using the financial library

        logMessage("Strategy deployment failed: ", string(e.what()));
        throw;
    }
}


// 3. Dynamic Strategy Loading

void deployStrategyFromFile( const string& filePath ){
    try{
        ifstream file(filePath);          // this opens a file stream using filepath
        if (!file.is_open()) {
            throw runtime_error("Failed to open strategy file: " + filePath);        // if the file is fail to open then it throws a runtime error with descriptive massage indicating the failure to open the file
        }

        string strategyScript( (istreambuf_iterator<char>(file)), isthreambuf_iterator<char>());   //if the file is successfully opened, it reads the content of the file into a string named strategyScript  // it uses the constructor string that takes two istreambuf_iterator<char> paramaters to read the content from the file stream
 
        deployStrategy(strategyScript);
    }
    catch(const exception& e){
        cerr << "Error: " << e.what() << endl;
    }
}

// 4. Asynchronous Deployment


void deployStrategyAsync( const string& strategyScript){

    future<void> deploymentFuture = async(launch::async, deployStrategy, strategyScript);    // The line of code asynchronously launches the deployStrategy function with the specified strategyScript using std::async. The result is stored in the deploymentFuture object

    cout << "Performing other tasks while waiting for deployment..." << endl;


    try{
        deploymentFuture.get();
        cout << "Strategy deployment completed succuessfully." << endl;
    }
    catch(const exception& e){
        cerr << "Error during strategy deployment: " << e.what() << endl;
    }
}



string  simulateAsyncTask( const httplib::Request& req){    // simulating an asynchronous task  // simulateAsyncTask: This function simulates an asynchronous task that takes some time to complete. It sleeps for 2 seconds (representing a time-consuming operation) and returns a string
    this_thread::sleep_for(chrono::seconds(2));  

    return "Async result for request: " + req.body;  
}

future<string> handleAsyncRequest( const httplib::Request& req){     // Asynchronous function to handle HTTP request
    return async(launch::async, [&req]() {
        return simulateAsyncTask(req);
    });
}


vector<httplib::WebSocket> clients;     //Maintaining a vector (clients) to store Websocket connections

unordered_map<string, string> strategyMappings;    // store strategy names and their corresponsing scripts
unordered_map<httplib::WebSocket*, unordered_set<string>> subscriptions;     //an ordered map where keys are pointers to websocket instances and values are sets of strategy names subscribed by each Websocket client

void broadcastMassage( const string& massage){     // this function is defined to send a text massage to all conected clients. it itarets over the clients vector and sends the massage to each client
    for ( auto& client : clients){
        client.send(massage.c_str(), massage.length(), httplib::WebSocketMessageType::TEXT) ;    // c_str is member of string class. it returns a pointer to a null terminated array of characters ( C-style string)  // the purpose of this function is to provie compatibility with C-style strings when interacting with functions
    }
}

void broadcastMassagetoSubscribers( const string& strategy, const string& massage){            // this function is defined to bpradcast a massage only to clients subscribed to a specific strategy. it checks if a client is subscriibed to the given strategy before the massage
    for(auto& client : clients){
        if(subscriptions[&client].count(strategy) > 0){
            client.send(massage.c_str(), massage.length(), httplib::WebSocketMessageType::TEXT);
        }
    }
}


void handleWebSocket( const httplib::Request& /*req*/, httplib::WebSocket& ws){
    clients.push_back(ws);                         // making a function to handle Websocket functions. when a new websocket connection is established, it is added to clients vector
    subscriptions[&ws] = {};                 //  Initialize empty set of subscriptions for the client           .&ws -----> & is used to obtain the memory address of the httplib::WebSocket object ws.

    while(true){

        auto msg = ws.recv();
        if( msg->type == httplib::WebSocketMessageType::CLOSE){      // if the massage type is close it means the websocket is closing. in this case corresponding wbsocket os removed from the client vector
            clients.erase(remove(clients.begin(), clients.end(), ws), clients.end());
            subscriptions.erase(&ws);         // basically this line says remove the entry associated with the Websocket client 'ws' from the subscriptions map
            break;
        }
        else if (msg->type == httplib::WebSocketMessageType::TEXT){          // this checks if the recieved WebSocket massage is of type TEXT
            string recievedMassage = msg->data;                     // it retirieves the actual content of the TEXT  massage and stores it in the recieved massage  variable

            if( recievedMassage == "get_strategies"){
                string strategyList = "Deployed Strategies: ";
                for ( const auto& entry : strategyMappings){
                    strategyList += entry.first + ", ";
                }
                ws.send(strategyList.c_str(), strategyList.length(), httplib::WebSocketMessageType::TEXT);

            }
            else if( recievedMassage.substr(0, 9) == "subscribe"){          // this substr(0,9) function is used to extract a substring from a string ( position 0 to 9) // in other words recievedmassage.substr(0, 9) extracts the first 9 characters of the recievedmassage string
                string strategyToSubscribe = recievedMassage.substr(10);      // this line extracts the strategy name from the recieved massage
                subscriptions[&ws].insert(strategyToSubscribe);              // this inserts the strategy name into the set of subscribed strategies for the Websocket client in 'subscription' map
                string subscriptionMassage = "Subscribed to updates for strategy '" + strategyToSubscribe + "'.";
                ws.send(subscriptionMassage.c_str(), subscriptionMassage.length(), httplib::WebSocketMessageType::TEXT);             // this sends subscription confirmation massage to the client
                
            }
            else{
                broadcastMassagetoSubscribers(recievedMassage, recievedMassage);        // this function calls to broadcast the recieved massage to all subscribers
            }


void adjustRiskThresholdDynamically( double& riskThreshold){

    double markeVolatility = getMarketVolatility();                       // this getMarketVolatility() function should be designed to retrieve the current market volatility from our system or external data source.
    riskThreshold = 0.02 + 0.005*markeVolatility;
}


string getCurrentTimestamp() {
    auto now = chrono::system_clock::now();
    auto time_point = chrono::system_clock::to_time_t(now);         // this function uses the <chrono> library to get the current systemtime, converts it to a time_point and then converts that time_point to a string using ctime. The resulting string is the current timestamp
    return ctime(&time_point);                                                                      
}      // this function is from EnhLogMech.cpp ( had to copy this function because otherwis in generationRiskreport function's have getcurenttimestamp used)           

void generationRiskReport( const vector<string>& strategyNames, const vector<double>& riskExposures){
    ofstream reportFile("risk_report.txt", ios::app);
    if(reportFile.is_open()) {
        reportFile << "Risk Report - " << getCurrentTimestamp() << "\n";
        for( size_t i=0; i<strategyNames.size(); ++i) {
            reportFile << strategyNames[i] << ": "  << fixed << setprecision(4) << riskExposures[i] << "\n"; // fixed does swtches to fixed point notation and setpecision sets the 4 digitsto the after the decimal point
        }
        reportFile << "\n";
        reportFile.close();
    }
//This function generates a risk report and writes it to a file named "risk_report.txt". It includes the names of strategies and their corresponding risk exposures. It utilizes the getCurrentTimestamp function for timestamping.
}

double getPortfolioSize() {
    double portfolioSize = 10000.0;
    return portfolioSize;
}

void dynamicPositionSizing( double& positionSize, double riskExposure ){
    double portfolioSize = getPortfolioSize();
    positionSize = 0.1 * portfolioSize/ riskExposure;
// this function dynamicaly adjusts the position size bases on risk exposure and the portfolio size. I assumes the existnce of a getPortfolioSize function that provides the current portfolio size    
}

void realTimeRiskMonitoring(const vector<string>& strategyNames, const vector<double>& riskExposures) {
    cout << "Real-Time Risk Monitoring:\n";
    for (size_t i = 0; i < strategyNames.size(); ++i) {
        cout << strategyNames[i] << ": " << fixed << setprecision(4) << riskExposures[i] << "\n";
    }
    cout << "\n";
    //This function prints real-time risk monitoring information for each strategy to the console.
}


void applyUserDefinedRiskRules( double & riskExpoture ){
    double maxRisk = 0.05;    // replace with the actual user-defined value
    riskExpoture = min(riskExpoture, maxRisk);
    //This function applies user-defined risk rules, such as limiting the maximum risk exposure. It uses std::min to enforce the defined limit.
}

void encryptData( const string& plaintext, string& ciphertext) {   // non-const string&(reference to string) as ciphertext output

    const string key = "0123456789abcdef";    // define a encryption key ( 16 bytes each)
    const string iv = "0123456789abcdef" ;    // defining an initialization vector( iv ) as strings ( 16 bytes each)

    CryptoPP::SecByteBlock keyBytes( reinterpret_cast<const byte*> (key.data()), key.size());        // SecByteBlock is a class provided by Crypto++ //  this reinterpret_cast is converting the data pointer of the string(key.data()) into a pointer to const byte
    CryptoPP::SecByteBlock ivBytes( reinterpret_cast<const byte*> (iv.data()), iv.size());   //In summary, this line of code converts a std::string representing a key into a CryptoPP::SecByteBlock, which is a more secure and suitable type for cryptographic operations. The key's raw memory is treated as an array of bytes, and the size of the key is specified. This is a common step when working with cryptographic libraries like Crypto++

    CryptoPP::AES::Encryption aesEncryption( keybytes, CryptoPP::AES::DEFAULT_KEYLENGTH);       // CryptoPP::AES::Encryption aesEncryption this lines set up an AES encryption object(aesEncryption)  // CryptoPP::AES::DEFAULT_KEYLENGTH specifies the key length (128, 192, or 256 bits) based on the length of the provided key.
    CryptoPP::CBC_Mode_ExternalCipher::Encryption cbcEncryption( aesEncryption, ivBytes);        //  CryptoPP::CBC_Mode_ExternalCipher::Encryption cbcEncryption This lines set tp a CBC ( Cipher Block Chaining) mode encryption object         // In summary, these two lines of code initialize AES encryption in CBC mode. The aesEncryption object is used as the block cipher, and the cbcEncryption object is set up to perform encryption using CBC mode with the specified key and initialization vector (ivBytes). This configuration is suitable for secure encryption of data using AES in CBC mode.

    CryptoPP::StringSource(plaintext, true,             //StringSource is a class that allows data to read from a string // It initialize a data source with the input plaintext // the true argument indicates that the StringSource object should throw as exception if an error occurs
        new CryptoPP::StreamTransformationFilter(cbcEncryption,         // CryptoPP::StreamTransformationFilter is a filter that performs a stream transformation on the input data     // It is configured to use the previously defined cbcEncryption object, which represents AES encryption in CBC mode
             new CryptoPP::HexEncoder(                                    // CryptoPP::HexEncoder is a filter that encodes binary data into its hexadecimal representation. // It is configured to convert the output of the AES encryption (binary ciphertext) into hexadecimal format
                 new CryptoPP::StringSink(ciphertext),                      // CryptoPP::StringSink is a sink that stores the output data in a std::string  // It is configured to store the hexadecimal-encoded ciphertext.           //THE ENCTYPTED DATA IS STORED IN THE "CIPHERTEXT" STRING
                     false           ) 
                                                )   // StreamTransformationFilter: Applies the encryption algorithm to the data.     //HexEncoder: Converts the encrypted binary data to a hexadecimal representation.            //StringSink: Collects the final ciphertext.
                        );            // In summary, this code snippet processes the plaintext using AES encryption in CBC mode, then converts the resulting ciphertext to a hexadecimal representation and stores it in the ciphertext string.
}



// these below functions show how to authenticate users before allowing access to a secured point

bool authenticateUser( const httplib::Request& req){
    sting token = req.get_header_value("Authorization");         // get_header_value("Authorization"): This method is used to retrieve the value associated with the "Authorization" header from the HTTP request. It returns the value as a string.
    return (token == "secret token");   // this has to replace wit actual secret token used from authentication system
}

void secureEndpoint( const httplib::Request& req, const httplib::Response& res){
    if(!authenticateUser(req)){
        res.status = 401;
        res.set_content("Authentication failed", "text/plain");
        return;
    }

    res.status = 200;
    res.set_content("Authenticated. Access granted to the secured endpoint.", "text/plain");
}

//These below functions are use to enable( HTTPS (SSL/TLS) for secure communication between clients and the server)


SSL_CTX* createSSLcontext(){                                                    // this function creates and coonfigures an OPENSSL SSL context. it loads the SSL certificate and private key ( In real world we need to obtainb a valid SSL certicate from a certificate autority)
    SSL_CTX* ctx = SSL_CTX_new(TLS_server_method());

    SSL_CTX_use_certificate_file(ctx, "server.crt", SSL_FILETYPE_PEM);
    SSL_CTX_use_PrivateKey_file(ctx, "server.key", SSL_FILETYPE_PEM);

    return ctx;
}

void configureServerSSL( httplib::Server& server){          // this function configures the httplib server to use SSL
    SSL_CTX* sslContext = createSSLcontext();
    server.ssl = sslContext;
}

// spdlog is a loggin library that provided fast and efficient logging for C++ application

auto logger = spdlog::stdout_logger_mt("logger");   // Initialize the logger //The stdout_logger_mt creates a logger that outputs to the console.

void logEvent( const string& massage){
    logger->info("Event: {}", massage);
}

void logError( const string& errorMassage){
    logger->error("Error: {}", errorMassage);
}

void handleRequest( const httplib::Request& req, const httplib::Response& res){

    logEvent("Recieved request");

    if(req.get_param_value("simulate_error") == "true" ){
        logError("Simulated error occured");
        res.status = 500;  // Internal Server Error
        res.set_content("Internal Server Error", "text/plain");
    }
    else{
        res.set_content("Request handled successfully", "text/plain");
    }

    //The handleRequest function is intended to handle an HTTP request. It starts by logging an event ("Received request") using the logEvent function. It then checks if a query parameter named "simulate_error" is set to "true". If so, it logs an error message ("Simulated error occurred") using the logError function, sets the HTTP response status to 500 (Internal Server Error), and provides an error message in the response content. If the query parameter is not set or is set to a value other than "true", it sets the HTTP response content to "Request handled successfully".
}


void logTradeExecution( const string& strategyScript){                 // placeholder function for logging trade execution
    ofstream tradeLogFile("trade_execution_log.txt", ios::app);
    tradeLogFile << "Trade execution for strategy: " << strategyScript << " at " << getCurrentTimeStamp() << "\n";
    tradeLogFile.close();
}

void logPerformanceMetrics( const string& strategyScript){                // placholdeer function for logging performance metrics
    ofstream metricsLogFile("performance_metrics_log.txt", ios::app);
    metricsLogFile << "Performance metrics for strategy: " << strategyScript << " at " << getCurrentTimeStamp() << "\n";
    metricsLogFile.close();
}

void deployStrategy( const string& strategyScript){
    bool isCompliant = true;   

    if(!isCompliant){
        ofstream logFile("compliance_log.txt", ios::app);             // thisoppppppens (txt file) in append mode
        logFile << "Regulatory compliance violation - " << getCurrentTimeStamp << "\n";
        logFile.close();
        return;
    }

    logTradeExecution(strategyScript);
    logPerformanceMetrics(strategyScript);
}




int main(){

    httplib::Server server;             // This Server class is provided by httplib library and represents an HTTP server

    server.Get("/", [](const httplib::Request& req, httplib::Response& res) {      // this is a Lambda Function           
        res.set_content("Hello World!", "text/plain");                              // his set_content method is used for response that Hello world with the content type of text/plain
    } );

    server.Post("/execute_trade", [] (const httplib::Request& req, httplib::Response& res) {    // this server.Post is used to define a handler for HTTP POSt requests. it is allows you to associate a handler function with a specific path for POST rquests
        res.set_content("Trade Executed!", "text/plain");
    });

    server.Post("/deployStrategy", handleDeployement);

    httplib::Client client("localhost", 8080);     // connect to a sever at localhost on port 8080

    server.WebSocket("/ws", [](const httplib::Request& req, httplib::WebSocket& ws) {  //Websockt handler is defined using server.Websocket for the path "/ws"
        while(true){
            auto msg = ws.resv();        // this is to recieve a websocket massage

            if( msg->type == httplib::WebSocketMessageType::CLOSE){   // when CLOSE massage received, loop gonna break( close the websocekt connection )
                break;
            }
            else if( msg->type == httplib::WebSocketMessageType::TEXT){    // if the recieved massage type is TEXT , the server sends the same text massage back to the client using ws.send(msg->data)
                ws.send(msg->data);
            }
        }
    });


    auto res = client.websocket("/ws", [&](const httplib::Request& req, httplib::WebSocket& ws){     // [&] it is used to specify how variables from the surrounding scope should be captured and made available inside the lambda function. in this case [&] indicated a captur by reference

        ws.send("Hello, WebSocket!");        // this line sends a to the server

        ws.on_message([&](const httplib::WebSocket::Message& msg){     // ws.on_massage function sets up a callback that is executed whenever a massage is received from the server

        });

    });


    server.Post("/deployStrategy", handleDeployement);     // "/deployStrategy is a endpoint"


    server.set_error_handler([](const httplib::Request& /*req*/, httplib::Response& res){      // this set_error_handler is used for custom error handling function for the HTTP server and it takes Lambda function as an argument
        res.status = 400;
        res.set_content("Bad Request", "text/plain");
    });    // In summary, this custom error handler is set to respond with a "Bad Request" message and a status code of 400 for any general errors that occur during the handling of HTTP requests.



    server.set_error_handler([] (const httplib::Request& /*req*/, httplib::Response& res){
        cerr << "Bad Request: Invalid client request" << endl;

        res.status = 400;
        res.set_content("Bad Request", "text/plain");
    });

    // Handling Not Found (404) Errors

    server.set_error_handler([] (const httplib::Request& /*req*/, httplib::Response& res){
        cerr<< "Not Found: Requested resource not found" << endl;

        res.status = 404;
        res.set_content("Not Found: Requested resource not found", "text/plain");
    });



    Strategy strategy1;
    Strategy strategy2;
    Strategy strategy3;

    vector<thread> strategyThreads;
    vector<Strategy> strategies = { strategy1, strategy2, strategy3};

    //1.parallel strategy evaluation ( enable parallel evealuation of multiple trading strategies concurrently)
    for( auto& strategy : strategies){
        strategyThreads.emplace_back( [&]() {     // emplace_back is used to add new element (in this case a thread) at the end of the strategyThreads container    // this[&] captures all variablesin the current scope by reference
            strategy.evaluate();
        });
    }

    for( auto& thread : strategyThreads){
        thread.join();                  // join is a function of the thread class // essentially thread.join() is used to synchronize the main thread with the threads in strategyThreads
    }

/*
Putting it all together, this code snippet is creating threads for each strategy in the strategies container. It iterates through each strategy, and for each strategy, it creates a new thread using a lambda expression. The lambda expression captures the strategy by reference (&) and calls the evaluate method on that strategy. The threads are then added to the strategyThreads container.

*/

    //2.concurrent order execution  ( to handle multiple trading orders simultaneously)

    vector<thread> orderThreads;
    vector<int> pendingOrders = { 1,2,3,4,5};        // sample pendingOrder vector (not real values)

    for (auto& order : pendingOrders) {
        orderThreads.emplace_back([&]() {
            executeOrder(order);
        });
    }

    for(auto& thread : orderThreads) {
        thread.join();
    }

/*
I've used a placeholder for pendingOrders (a vector of integers), and executeOrder is a function that simulates the logic for executing an order. The code creates threads for each order in pendingOrders using a lambda function, and then waits for all threads to finish using join in a subsequent loop

*/    

    //3.Parallel Market Data handling ( utilize multithreading to efficiently handle incoming market data feeds)


    MarketDataFeed dataFeed1;
    MarketDataFeed dataFeed2;
    MarketDataFeed dataFeed3;

    vector<thread> dataFeedThreads;
    vector<MarketDataFeed> marketDataFeeds = {dataFeed1, dataFeed2, dataFeed3};


    
    for( auto& dataFeed : marketDataFeeds){
        dataFeedThreads.emplace_back( [&]() {     // emplace_back is used to add new element (in this case a thread) at the end of the strategyThreads container    // this[&] captures all variablesin the current scope by reference
            dataFeed.processMarketData();
        });
    }

    for( auto& thread : dataFeedThreads){
        thread.join();                  // join is a function of the thread class // essentially thread.join() is used to synchronize the main thread with the threads in strategyThreads
    }

/*
MarketDataFeed is a placeholder class, and instances of this class (e.g., dataFeed1, dataFeed2, etc.) are created. These instances are then added to the marketDataFeeds vector, and the vector is used in the loop to create threads for parallel processing of market data feeds

*/ 

    server.set_thread_pool_size(4);     // this line sets the number of threads in the server's thread pool.  By setting this the thread size, you can control how many parallel tasks the server can handle simultaneously. in this case set to 4 threads.

    server.WebSocket("/ws", handleWebSocket);    // extending the server to handle websocket connctions. new websocket endpoint is "/ws"


    server.listen("localhost", 8080);                    // 8080 is a port number and localhost is a special IP address used to refer a local machine//when we run this code HTTP server will be accessible at http://localhost:8080 from  web browser or any HTTP client // port 8080 is commonly used for Http servers and it is an defualt HTTp port(port 80). using a port number greater than 1024 is a common practise to avoid requiring any privilages

    string strategy ="buy(symbol) && sell(symbol)";

    if(validateStrtegy(strategy)){
        cout << "Strategy validation passed!" << endl;
    }
    else{
        cerr << "Strategy validation failed." << endl;
    }

    deployStrategyAsync("ExampleStrategyScript");            // we have to replac withing the actual content


    server.Post("/endpoint", [](const httplib::Request& req, httplib::Response& res){
        auto asyncTaskFuture = handleAsyncRequest(req);

        cout << "Handling other synchronous work.." << endl;

        string result = asyncTaskFuture.get();

        res.set_content(result.c_str(), "text/plain")
    });

    // main: Inside the main function, when handling an HTTP request asynchronously, we obtain a std::future for the asynchronous task by calling handleAsyncRequest(req). While waiting for the asynchronous task to complete, the server can perform other synchronous work (e.g., print a message).
    // Result Handling: Once the asynchronous task is complete, we retrieve the result using asyncTaskFuture.get() and set it in the HTTP response.

    double positionSize;
    double riskExposure = 5000.0;

    dynamicPositionSizing(positionSize, riskExposure);


    adjustRiskThresholdDynamically(riskTheshold);
    generationRiskReport( strategyNames, riskExposure);
    dynamicPositionSizing(positionSize, riskExposures[0]);
    realTimeRiskMonitoring(strategyNames, riskExposures);
    applyUserDefinedRiskRules(riskExposures[0]);


    server.Get("/secured", secureEndpoint);            // "/secured" this is a secured endpoint
    server.listen("localhost", 8080);


    string plaintext = " This is senstive data";
    string ciphertext;

    encryptData(plaintext, ciphertext);     // Encrypt the data


    configureServerSSL(server);   // configure server to use SSL

    server.Get("/", []( const httplib::Request& req, httplib::Response& res){ // diffeent endpoints because we have different server PORTS
        res.set_content("Hello, Secure World!", "text/plain");     // handle HTTP GEt request
    });

    server.listen("localhost", 8443)

    spdlog::set_level(spdlog::level::info);  // sets the logging level to log events and errors
    server.Get("//", handleRequest);

    return 0;
}