using Microsoft.Data.SqlClient;
using System.Data;

namespace Authentication.Data;

public class DatabaseConnection : IDatabaseConnection
{
    private readonly string _connectionString;

    public DatabaseConnection(string connectionString, string schema)
    {
        schema = schema.Replace("[", string.Empty).Replace("]", string.Empty);
        _connectionString = connectionString;
        DbSchema = schema;
    }
    public async Task<SqlConnection> CreateConnectionAsync()
    {
        var sqlConnection = new SqlConnection(_connectionString);
        if (sqlConnection.State != ConnectionState.Open)  await sqlConnection.OpenAsync();
        return sqlConnection;
    }
    
    public string DbSchema { get; set; }
}