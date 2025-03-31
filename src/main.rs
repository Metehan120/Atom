use atom::*;

#[tokio::main]
async fn main() {
    set_algorithm(atom::Algorithms::ZSTD).unwrap();
    set_password("testpassword").unwrap();

    add_data_block(vec!["test.txt" /* ... */], "test", false).await.unwrap();
    remove_data_block(vec!["test.txt" /* ... */], "test").await.unwrap();
    export_file(vec!["test.txt" /* ... */], "test").await.unwrap();
    read_data_block("test.txt", "test").await.unwrap();
    read_multiple_data_block(vec!["test.txt" /* ... */], "test").await.unwrap();
    update_data_block(vec!["test.txt" /* ... */], "test", false).await.unwrap();
}
