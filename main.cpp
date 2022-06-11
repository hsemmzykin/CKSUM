#include <iostream>
#include <fstream>
#include <filesystem>
#include <string>
#include <sstream>
#include <utility>
#include <vector>
#include <algorithm>
#include <map>
#include <regex>
#include <utility>
#include <unordered_map>
#include <vector>
#include <memory>
#include <fstream>
#include <sys/stat.h>
#include <cctype>
#include <experimental/string_view>
#include <set>
#include <cstdint>
#include <sstream>
#include <cstdio>
#include "mIniParser.h"
#include "SHA.h"
#include "md5.h"
#include <filesystem>
#include <boost/program_options.hpp>
#include <boost/algorithm/string/trim.hpp>
#include <any>

using namespace mINI;
using namespace std::filesystem;
namespace po = boost::program_options;
namespace Utils {

    std::string readAllText(const std::string& path) {
        std::ifstream infile(path);
        if (infile.fail()) {
            throw std::invalid_argument{ "Unable to read file at path: '" + path + "'" };
        }
        infile.ignore(std::numeric_limits<std::streamsize>::max());
        std::streamsize size = infile.gcount();
        infile.clear();
        infile.seekg(0, std::ifstream::beg);
        std::string contents(size, ' ');
        infile.read(&contents[0], size);
        return contents;
    }


    void writeAllText(const std::string& path, const std::string& contents) {
        std::ofstream outfile(path);
        if (outfile.fail()) {
            throw std::invalid_argument{ "Unable to write file at path: '" + path + "'" };
        }
        outfile << contents;
    }
    static std::vector<char> readAllBytes(const std::string& filename)
    {
        std::ifstream ifs(filename, std::ios::binary|std::ios::ate);
        std::ifstream::pos_type pos = ifs.tellg();

        if (pos == 0) {
            return std::vector<char>{};
        }

        std::vector<char>  result(pos);

        ifs.seekg(0, std::ios::beg);
        ifs.read(&result[0], pos);

        return result;
    }
}

using namespace Utils;

std::string ssystem (const char *command) {
    char tmpname [L_tmpnam];
    std::tmpnam ( tmpname );
    std::string scommand = command;
    std::string cmd = scommand + " >> " + tmpname;
    std::system(cmd.c_str());
    std::ifstream file(tmpname, std::ios::in | std::ios::binary );
    std::string result;
    if (file) {
        while (!file.eof()) result.push_back(file.get());
        file.close();
    }
    remove(tmpname);
    return result;
}
void printInfo(){
    std::string bash = R"lit(find . -type f -exec sh -c 'printf "%s %s %s \n" "$(ls -l $1)" "$(md5sum $1)" "$(sha1sum $1)"' '' '{}' '{}'  \;)lit";
    std::string in;
    std::string s = ssystem(bash.c_str());
    std::istringstream iss(s);
    std::string line;
    while (std::getline(iss, line)){
        std::cout <<  line  << std::endl;
    }
}
// int flag = {1 -- for md5, 2 -- for sha};
static int flag = 1;
std::string algo(const std::string& pathToFile, int flag = 1){
    if (flag == 1){ //md5
        auto f = readAllBytes(pathToFile);
        return md5(f);
    }
    else {
        return SHA1::from_file(pathToFile);
    }
}
struct IniParser{
private:
    INIFile fil;
    INIStructure data;
    std::map<std::string, std::string> dataList = std::map<std::string, std::string>();
public:
    explicit IniParser(const std::string& file = "./cksum.ini") : fil(file){fil.read(data);
        makeSection("sum");}

    void writeToINI(const std::string& section, std::pair<std::string, std::string> x){
         data[section].set(x.first, x.second);
         fil.write(data);
    }


    void setNewHash(const std::string& file, std::string sum){
        dataList[file] = std::move(sum);
    }
    void makeSection(std::string sectionName = "newfiles"){
        data[std::move(sectionName)];
        fil.write(data);
    }
    int size(){
        return dataList.size();
    }
    void fileSysDiff(){
        makeSection("newfiles");
        for (const auto& x : std::filesystem::directory_iterator("./")){
            std::string file = x.path().string();
            if (file == "./cksum.ini" || std::filesystem::is_directory(file)){
                continue;
            }
            std::string fileSeized = file.substr(2, file.size() - 1);
            if (dataList.find(fileSeized) == dataList.end()){
                writeToINI("newfiles", {fileSeized, algo(file)});
            }
        }
    }
    void readDataINI(){
        for (const auto& it : data){
            auto const& sect = it.first;
            auto const& collection = it.second;
            for (const auto& it2 : collection){
                dataList[it2.first] = it2.second;
            }
        }
    }
    void countSum(int flag){
        for (const auto& x : dataList){
            if (std::filesystem::exists("./" + x.first) && x.first != "cksum.ini")
                dataList[x.first] = flag == 1 ? md5(readAllBytes("./" + x.first)) : SHA1::from_file("./" + x.first);
        }
        for (auto& x : dataList){
            writeToINI("sum", x);
        }
    }
    void printData(){
        for (const auto& x : dataList){
            std::cout << x.first << " " << x.second <<  '\n';
        }
    }
};

// -f - read from file, -s - SHA1 sum, -t - write to out.txt, -c -- use files as .ini files

// use boost::po library for parsing arguments
/*
 * [-h | --help]        HELP
 * [-V | --version]     Display Version Information
 * [-f | --file]        Write data to file
 * [-S | --SHA]         Use SHA algo
 * [-c | --check]       Treat input files as multiple .ini files
 * no options (just files)  Print files' control  sums into console
 */

int main(int argc, char** argv) {
    if (argc == 1) {
        if (!std::filesystem::exists("./cksum.ini")) {
            std::cerr << "No file cksum and/or options\n";
            exit(1);
        } else {
            IniParser INI("./cksum.ini");
            INI.readDataINI();
            if (INI.size() == 0) {
                std::cerr << "EMPTY CKSUM\n";
                INI.fileSysDiff();
                exit(1);
            }
            INI.countSum(1);
            INI.fileSysDiff();
            INI.printData();
        }
    }

    po::options_description description("Usage: ");
    description.add_options()
            ("help", "NO ONE CAN HELP YOU HAHAHA")
            ("version", "1.4.8.7")
            ("sha", "change algorithm to sha")
            ("md5", "change algorithm to md5sum")
            ("file", po::value<std::string>(), "Writing to this file")
            ("read", po::value<std::vector<std::string>>(), "Checking these files' cksums")
            ("check", po::value<std::vector<std::string>>(),"Treating provided INI files as separate cksums'");
    po::positional_options_description p;
    p.add("read", -1);
    po::variables_map vm;
    po::store(po::command_line_parser(argc, argv).options(description).positional(p).run(), vm);
    po::notify(vm);

    if (vm.count("help")){
        std::cout << description << std::endl;
    }
    if (vm.count("version")){
        std::cout << "1.4.8.6" << std::endl;
    }
    if (vm.count("file")){
        std::string filename = vm["file"].as<std::string>();
        std::string filename_path = "./" + filename;
        if (!std::filesystem::exists(filename_path)){
            std::cout << "FILE DIDN'T EXIST. CREATING ONE!\n";
            FILE * file_ptr = fopen(filename.c_str(), "w");
            fclose(file_ptr);
        }
        if (std::filesystem::exists(filename_path) && !std::filesystem::is_directory(filename_path)) {
            std::ofstream out(filename_path, std::ofstream::out);
            if (out.is_open()) {
                for (const auto &x: std::filesystem::directory_iterator("./")) {
                    if (!std::filesystem::is_directory(x.path().string())) {
                        out << x.path().string().substr(2, x.path().string().size() - 1) << " : " << algo(filename_path, flag) << "\n";
                    }
                }
            }
            out.close();
            std::cout << filename << " was successfully filled\n\n";
    }
}
    if (vm.count("sha")){
        flag = 2;
    }
    if (vm.count("md5")){
        flag = 1;
    }
    if (vm.count("read")){
        for (const auto& x : vm["read"].as<std::vector<std::string>>()){
            if (!std::filesystem::is_directory("./" + x) && x != "cksum.ini")
                std::cout << x << " : " << algo("./" + x, flag) << std::endl;
        }
    }
    if (vm.count("check")) {
        if (vm["check"].as<std::vector<std::string>>().empty()) {
            if (!std::filesystem::exists("./cksum.ini")) {
                std::cout << "No files provided\n\n";
            } else {
                IniParser cksum("./cksum.ini");
                cksum.readDataINI();
                if (cksum.size() == 0) {
                    std::cout << "EMPTY " << "CKSUM.INI FILE!\n";
                    cksum.fileSysDiff();
                }
                cksum.countSum(flag);
                std::cout << "no additional files provided. file ./cksum.ini  successfully checked\n\n";
            }
        }
        else {
            std::vector<std::string> inis;
            for (const auto &x: vm["check"].as<std::vector<std::string>>()) {
                inis.push_back(x);
            }
            for (const auto &x: inis) {
                if (std::filesystem::exists("./" + x)) {
                    IniParser pars("./" + x);
                    pars.readDataINI();
                    if (pars.size() == 0) {
                        std::cerr << "EMPTY " << x << " INI FILE!\n";
                        pars.fileSysDiff();
                        continue;
                    }
                    pars.countSum(flag);
                    pars.fileSysDiff();
                    std::cout << "file " << x << " successfully checked\n\n";
                }
                else{
                    std::cout << x << " <- this ini doesn't exist\n";
                    continue;
                }
            }
        }
    }
#ifdef PRINTDATA
    printInfo();
#endif
}


//documentation I used (not copypasted)


// https://github.com/pulzed/mINI
// https://stackoverflow.com/questions/5007268/how-to-call-linux-command-from-c-program