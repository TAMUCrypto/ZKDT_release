#include <iostream>
#include <algorithm>
#include <stdexcept>
#include <cstdlib>
#include <fstream>
#include <sstream>
#include <map>
#include <string>
#include <iterator>

#include "DT/DT.h"

using namespace std;

std::map<std::string, int> map_of_classes;

DT *_read_dt_from_file(string filename){
    int class_id = 0;
    bool isleft = true;
    DT *dt = new DT();

    ifstream input;
    input.open(filename.c_str()); 

    if(input.is_open()){
       std::string line;
       DTNode* current_node = nullptr;
       DTNode* tmp = nullptr;
       while(getline(input, line)){

           //if(current_node != nullptr)
           //   cout << "current_node->node_id = " << current_node->node_id << endl; //current node.
          //printf("%s\n", line.c_str());
          for(int i = 0; i < line.size(); i++){
            if(line[i] == ':'){
            //  cout << "get in " << endl;
            //  cout << line.substr(i+2) << endl;
              string classification = line.substr(i + 2);
              //cout << classification << endl;
              if(map_of_classes.find(classification) != map_of_classes.end()){
                //cout << "it is ok till now" << endl;
                class_id = map_of_classes[classification];
              }
                else
                  map_of_classes.insert(std::make_pair(classification, ++class_id)); 
              //  if(current_node->node_id == 0){
              //    cout << "isleft = " << isleft << " " << "node_id = " << dt->n_nodes << endl;
              //  }
            
                tmp = dt->add_leaf_node(current_node, isleft, class_id);
              //  cout << "tmpid = " << tmp->node_id << endl;
                if(isleft == false){
                  while(current_node != nullptr && current_node->r_visited)
                    current_node = current_node->parent;
                }
                //cout << "current_node->node_id = " << current_node->node_id << " " << "class_id = " << class_id << endl;
              break;
            }
            if(line[i] >= '0' && line[i] <= '9'){
              unsigned int j, variable_id_, threshold_;
              for(j = i; j < line.size(); j++){
                if(line[j] < '0' || line[j] > '9'){
                  variable_id_ = stoi(line.substr(i, j)) - 1;
                  //cout << "variable_id_ = " << variable_id_ << endl;

                  break;
                }
              }
              if(line[j + 1] == '<' && line[j + 2] == '='){
                threshold_ = stoi(line.substr(j + 4));
                 //cout << "threshold_ = " << threshold_ << endl;
                if(current_node == nullptr){
                  auto root = dt->add_internal_root(variable_id_, threshold_);
                  current_node = root;
                }
                else{
                  current_node = dt->add_internal_node(current_node, isleft, variable_id_, threshold_);
                }
                //if(current_node == nullptr || current_node->r_visited == false)
                  isleft = true;
                break;
              }
              if(line[j + 1] == '>'){
                current_node->r_visited = true;
                isleft = false;
                break;
              }
            }
          }
       }
       input.close();
    }
    //cout << "it is ok" << endl;
    return dt;
}

/*
int main(){
  DT * dt_model = _read_dt_from_file("/Users/cusgadmin/Desktop/ZKDT/Model/Iris_dt.txt");
  cout << "root_left_child_id = " << dt_model->root->l->node_id << endl;
  dt_model->print_dt(dt_model->root, 0);
  return 0;
}
*/


