using Microsoft.Data.SqlClient;

namespace Authentication.Data;

public interface IDatabaseConnection
{
    Task<SqlConnection> CreateConnectionAsync();
    string DbSchema { get; set; }
}